/**
 * autoruns_win.cpp — Windows leg of the autoruns plugin (P12).
 *
 * Implements yuzu::autoruns::collect_windows (autoruns_legs.hpp, P11):
 * HKLM Run/RunOnce/RunOnceEx (native + WOW6432Node views), Explorer
 * StartupApproved\{Run,Run32,StartupFolder} (system AND every reachable
 * per-user hive), Winlogon Shell/Userinit, AppInit_DLLs, Image File
 * Execution Options\*\Debugger, the common and per-user Startup folders,
 * Scheduled Tasks (ITaskService COM), and WMI permanent event subscriptions
 * (root\subscription). Per-user reads go through win_profiles.hpp's
 * with_user_hive ladder exclusively — no second offline-hive mount path,
 * and this file never enables a backup/restore privilege of its own.
 *
 * A1's the-rig probe (tests/unit/fixtures/wave7/probes/the-rig-probe-findings.md,
 * 2026-09-06), Probe 3, quoted verbatim:
 *
 *   "MTA works for ITaskService on the-rig, in both the admin session and
 *   under LocalSystem -- the repo's agents/shared/win_com.hpp:33-35
 *   COINIT_MULTITHREADED choice is not a problem for ITaskService here;
 *   both apartment models gave identical HRESULTs and counts in each
 *   session."
 *
 * Consequently this file uses yuzu::shared::win::ComInit (COINIT_MULTITHREADED)
 * directly on the calling thread — no dedicated STA thread, no
 * bounded_wait.hpp join, is needed for the Task Scheduler walk. WMI already
 * gets its own bounded enumeration from run_bounded_wmi_query, independent
 * of the apartment question.
 *
 * ComInit::ok() intentionally does not expose the underlying HRESULT (only
 * a bool), so the one COM failure this file cannot render as a real
 * `hr_<hex>` token is CoInitializeEx itself failing -- reported as the fixed
 * sentinel `hr_cominit_failed` below. Every other COM/WMI failure in this
 * file (CoCreateInstance, Connect, GetFolder, GetTasks, and every
 * run_bounded_wmi_query call) carries the real HRESULT or the shared
 * wmi_bounded.hpp error token.
 *
 * Zero spawn primitives: every source here is a direct Win32/COM/WMI read.
 * schtasks.exe, wmic.exe and PowerShell are never invoked.
 *
 * WMI subscription rows are emitted one per __FilterToConsumerBinding,
 * joined against the enumerated __EventFilter/__EventConsumer rows by the
 * ref's Name (autoruns_win_wmi_join.hpp, P12 respec delta 1) -- a dangling
 * ref (matches no enumerated row) still emits its row and marks the source
 * `constrained|unresolved_ref` rather than collapsing N bindings into one
 * row or silently dropping the unresolved one.
 */

#include "autoruns_catalog.hpp"
#include "autoruns_legs.hpp"
#include "autoruns_parsers.hpp"

#include <yuzu/plugin.hpp>

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shlobj.h>
#include <taskschd.h>

#include <win_com.hpp>
#include <win_profiles.hpp>
#include <win_reg_handle.hpp>
#include <wmi_bounded.hpp>

#include "autoruns_win_wmi_join.hpp"

#include <constraint_accumulator.hpp>

#include <cstdint>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace yuzu::autoruns {

namespace {

using yuzu::win::ReadValueStatus;
using yuzu::win::RegKey;

// ── small local helpers (pure; live here because autoruns_parsers.hpp is
//    P11's file and out of this package's scope) ─────────────────────────

/// `sources=` allow-list check (empty filter -> every source runs).
bool want(std::string_view filter, SourceId id) {
    if (filter.empty()) return true;
    const std::string_view id_str = source_id_string(id);
    std::size_t pos = 0;
    while (pos <= filter.size()) {
        const std::size_t comma = filter.find(',', pos);
        const std::string_view tok =
            comma == std::string_view::npos ? filter.substr(pos) : filter.substr(pos, comma - pos);
        if (tok == id_str) return true;
        if (comma == std::string_view::npos) break;
        pos = comma + 1;
    }
    return false;
}

/// Stable token for a non-ok ReadValueStatus -- fed into a source's
/// `constrained` reason, never dropped.
std::string_view read_status_token(ReadValueStatus st) {
    switch (st) {
    case ReadValueStatus::oversized:            return "oversized";
    case ReadValueStatus::malformed:            return "malformed";
    case ReadValueStatus::changed_during_read:  return "changed_during_read";
    case ReadValueStatus::not_found:            return "not_found";
    case ReadValueStatus::ok:                   return "ok";
    }
    return "ok";
}

/// Reads a MACHINE-scoped environment variable (identical for every user on
/// this host -- SystemDrive/SystemRoot/windir/ProgramData/etc., the
/// resolve_profile_shell_folder allowlist) from the agent's own process
/// environment via the wide API + yuzu::win::from_wide, matching
/// script_exec_plugin.cpp's identical two-pass GetEnvironmentVariableW
/// idiom. nullopt on "not set" OR any other failure -- resolve_
/// profile_shell_folder already treats a nullopt lookup result as
/// "startup_redirect_unresolved", so there is no separate error case for
/// this helper to distinguish.
std::optional<std::string> win_machine_env_var(std::string_view name) {
    const std::wstring wname = yuzu::win::to_wide(name);
    wchar_t stack_buf[256];
    DWORD len =
        GetEnvironmentVariableW(wname.c_str(), stack_buf, static_cast<DWORD>(std::size(stack_buf)));
    if (len == 0) return std::nullopt;
    if (len < std::size(stack_buf)) return yuzu::win::from_wide(stack_buf, static_cast<int>(len));

    // Value longer than the stack buffer: len is the required size
    // INCLUDING the terminating NUL on this branch (GetEnvironmentVariableW's
    // contract), so a len-sized buffer holds it exactly.
    std::wstring buf(len, L'\0');
    const DWORD len2 = GetEnvironmentVariableW(wname.c_str(), buf.data(), len);
    if (len2 == 0 || len2 >= len) return std::nullopt; // shrank or failed between the two calls
    return yuzu::win::from_wide(buf.c_str(), static_cast<int>(len2));
}

std::string_view hive_status_token(yuzu::win::HiveAccessStatus st) {
    switch (st) {
    case yuzu::win::HiveAccessStatus::ok:                return "ok";
    case yuzu::win::HiveAccessStatus::not_found:         return "not_found";
    case yuzu::win::HiveAccessStatus::privilege_missing: return "privilege_missing";
    case yuzu::win::HiveAccessStatus::mount_failed:      return "mount_failed";
    }
    return "not_found";
}

/// True when `status` (an LSTATUS from RegOpenKeyExW) reflects a
/// genuinely-absent key -- several of this leg's keys are legitimately
/// absent on a given host (RunOnceEx unused, no per-app IFEO override
/// configured, etc.), and "absent" is not this leg's error to report. Any
/// OTHER open failure -- ERROR_ACCESS_DENIED foremost -- is a real
/// constraint the caller must surface via note_constraint, never silently
/// folded into "zero rows" (AC4: failure != empty).
bool is_benign_absent_reg(LSTATUS status) noexcept {
    return status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND;
}

/// `LSTATUS` (from a failed RegOpenKeyExW) -> a stable reason token for a
/// `constrained` source status.
std::string_view reg_open_constraint_token(LSTATUS status) noexcept {
    switch (status) {
    case ERROR_ACCESS_DENIED: return "permission_denied";
    default:                  return "reg_open_failed";
    }
}

/// Reverses user_profile_model.hpp's hex_encode (2 hex chars/byte, no
/// delimiter) -- needed because read_reg_value hex-encodes REG_BINARY into
/// `out_value` and the StartupApproved blob parser wants raw bytes.
std::vector<unsigned char> hex_decode(std::string_view hex) {
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<unsigned char> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) break;
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return out;
}

std::int64_t filetime_to_unix(const FILETIME& ft) {
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    constexpr std::uint64_t kEpochDiff100ns = 116444736000000000ULL; // 1601 -> 1970
    if (uli.QuadPart < kEpochDiff100ns) return 0;
    return static_cast<std::int64_t>((uli.QuadPart - kEpochDiff100ns) / 10000000ULL);
}

std::int64_t reg_key_mtime(HKEY key) {
    FILETIME ft{};
    if (RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                         nullptr, nullptr, nullptr, &ft) == ERROR_SUCCESS)
        return filetime_to_unix(ft);
    return 0;
}

std::int64_t file_mtime(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data))
        return filetime_to_unix(data.ftLastWriteTime);
    return 0;
}

/// Minimal ISO-8601 "YYYY-MM-DDTHH:MM:SS[...]" -> Unix epoch seconds. A
/// trailing timezone offset (Task Scheduler's <Date> commonly carries one)
/// is ignored -- this is a best-effort mtime source for a row whose primary
/// timestamp signal (file/registry mtime) does not apply, not a validating
/// calendar parser. Returns 0 on anything that doesn't match the shape.
std::int64_t parse_iso8601_to_epoch(std::string_view s) {
    if (s.size() < 19) return 0;
    auto digit = [&](std::size_t i) -> int {
        if (i >= s.size() || s[i] < '0' || s[i] > '9') return -1;
        return s[i] - '0';
    };
    auto num = [&](std::size_t off, int width) -> int {
        int v = 0;
        for (int i = 0; i < width; ++i) {
            const int d = digit(off + static_cast<std::size_t>(i));
            if (d < 0) return -1;
            v = v * 10 + d;
        }
        return v;
    };
    if (s[4] != '-' || s[7] != '-' || (s[10] != 'T' && s[10] != ' ') || s[13] != ':' ||
        s[16] != ':')
        return 0;
    const int year = num(0, 4);
    const int month = num(5, 2);
    const int day = num(8, 2);
    const int hour = num(11, 2);
    const int minute = num(14, 2);
    const int second = num(17, 2);
    if (year < 0 || month < 1 || month > 12 || day < 1 || day > 31 || hour < 0 || hour > 23 ||
        minute < 0 || minute > 59 || second < 0 || second > 60)
        return 0;

    // Howard Hinnant's days_from_civil (public domain), avoids any TZ-
    // dependent libc calendar call.
    int y = year;
    const unsigned m = static_cast<unsigned>(month);
    const unsigned d = static_cast<unsigned>(day);
    y -= (m <= 2) ? 1 : 0;
    const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? static_cast<unsigned>(-3) : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    const std::int64_t days = era * 146097 + static_cast<std::int64_t>(doe) - 719468;
    return days * 86400 + hour * 3600 + minute * 60 + second;
}

std::string wstring_to_utf8(const std::wstring& ws) {
    return yuzu::win::from_wide(ws.c_str(), static_cast<int>(ws.size()));
}

std::wstring last_path_component(const std::wstring& path) {
    const auto pos = path.find_last_of(L'\\');
    return pos == std::wstring::npos ? path : path.substr(pos + 1);
}

// ── generic row/source-outcome plumbing ──────────────────────────────────

struct SourceOutcome {
    std::vector<Row> rows;
    yuzu::shared::ConstraintAccumulator acc;
};

void note_constraint(SourceOutcome& outcome, std::string_view token) {
    // Exact-string dedup (yuzu::shared::ConstraintAccumulator): an
    // unqualified token (e.g. "row_cap") repeating identically across many
    // profiles/iterations must not grow the reason string once per
    // occurrence (governance Gate 4 unhappy-path: an enterprise host with
    // hundreds of affected profiles could otherwise produce a reason
    // string hundreds of tokens long). A SID-qualified token (e.g.
    // "<sid>:privilege_missing") is unique per profile by construction, so
    // this dedup never collapses genuinely distinct per-profile failures --
    // only literal repeats. Matches autoruns_macos.cpp's identical
    // migration off the former substring-matching accumulation.
    outcome.acc.add_failure(token);
}

/// Returns true iff this source's own status resolved to CONSTRAINED -- lets
/// callers accumulate a leg-wide degradation aggregate without duplicating
/// the constrained/supported decision at every call site.
bool finish_source(yuzu::CommandContext& ctx, SourceId id, const SourceOutcome& outcome) {
    for (const auto& r : outcome.rows) ctx.write_output(format_row(r));
    const bool constrained = outcome.acc.any_failure();
    const std::string reason = outcome.acc.reason();
    ctx.write_output(format_source_status(
        id, constrained ? YUZU_SUPPORT_CONSTRAINED : YUZU_SUPPORT_SUPPORTED,
        outcome.rows.size(), constrained ? std::string_view{reason} : "ok"));
    return constrained;
}

/// A `sources=` filter excluding `id` must still report a status row for
/// it -- content/definitions/autoruns.yaml and docs/user-manual/autoruns.md
/// both guarantee every catalog source reports a status on every `list`
/// capture, "never omitted" -- so this is the sole dispatch point for every
/// Windows source's final status, matching the macOS leg's `filtered`
/// convention rather than silently emitting nothing. Returns true iff the
/// dispatched status resolved to CONSTRAINED (a `filtered` status is always
/// SUPPORTED, never counted) -- same aggregation contract as finish_source.
bool finish_source_or_filtered(yuzu::CommandContext& ctx, std::string_view filter, SourceId id,
                               const SourceOutcome& outcome) {
    if (want(filter, id)) {
        return finish_source(ctx, id, outcome);
    }
    ctx.write_output(format_source_status(id, YUZU_SUPPORT_SUPPORTED, std::nullopt, "filtered"));
    return false;
}

// ── 1. HKLM Run / RunOnce / RunOnceEx (native + WOW6432Node views) ───────

/// `key` must already be open (KEY_READ) -- this only enumerates+reads its
/// direct values, it never opens anything itself.
void collect_reg_values(HKEY key, const std::wstring& location, SourceId id, Scope scope,
                        std::string_view user, SourceOutcome& outcome) {
    auto names = yuzu::win::enumerate_value_names(key);
    if (!names.complete) note_constraint(outcome, "enumeration_incomplete");
    const std::int64_t mtime = reg_key_mtime(key);
    for (const auto& name : names.names) {
        std::string value, type_name;
        const auto st = yuzu::win::read_reg_value(key, name, value, type_name);
        if (st == ReadValueStatus::not_found) continue; // raced deletion; not a row

        Row row;
        row.source_id = id;
        row.catalog_version = kAutorunSourceCatalogVersion;
        row.location = wstring_to_utf8(location);
        row.entry = name;
        row.scope = scope;
        row.user = std::string{user};
        row.signed_state = Signed::not_checked;
        row.mtime = mtime;
        if (st == ReadValueStatus::ok) {
            const auto split = split_command_line(value);
            row.target = split.target;
            row.args = split.args;
            row.enabled = Enabled::unknown; // Run/RunOnce carry no on/off bit of their own
        } else {
            row.enabled = Enabled::unmodelled;
            note_constraint(outcome, read_status_token(st));
        }
        outcome.rows.push_back(std::move(row));
    }
}

void open_and_collect(HKEY hive, const std::wstring& subkey, REGSAM extra_view, SourceId id,
                     const std::wstring& location, Scope scope, std::string_view user,
                     SourceOutcome& outcome) {
    RegKey key;
    const LSTATUS status = RegOpenKeyExW(hive, subkey.c_str(), 0, KEY_READ | extra_view, key.put());
    if (status != ERROR_SUCCESS) {
        if (!is_benign_absent_reg(status)) note_constraint(outcome, reg_open_constraint_token(status));
        return;
    }
    collect_reg_values(key.get(), location, id, scope, user, outcome);
}

constexpr DWORD kMaxRunOnceExSubkeys = 4096;

/// RunOnceEx's real registration shape is a NUMBERED subkey per queued
/// command (e.g. "0001"), each holding one or more values whose data is the
/// command line to run -- Microsoft's own documented RunOnceEx mechanism.
/// `open_and_collect`'s direct-value read (still run, defensively, since
/// nothing forbids a value directly under RunOnceEx too) misses this shape
/// entirely: a real RunOnceEx-registered persistence mechanism was
/// previously never enumerated at all. One row per value per numbered
/// subkey, via the same collect_reg_values every other flat-value source
/// here uses.
void collect_runonceex_subkeys(HKEY hive, const std::wstring& subkey, REGSAM extra_view,
                               SourceId id, const std::wstring& location_prefix, Scope scope,
                               SourceOutcome& outcome) {
    RegKey key;
    const LSTATUS status = RegOpenKeyExW(hive, subkey.c_str(), 0, KEY_READ | extra_view, key.put());
    if (status != ERROR_SUCCESS) {
        if (!is_benign_absent_reg(status)) note_constraint(outcome, reg_open_constraint_token(status));
        return;
    }
    constexpr DWORD kNameBufLen = 256;
    wchar_t name_buf[kNameBufLen]{};
    DWORD idx = 0;
    DWORD name_len = kNameBufLen;
    LSTATUS enum_status = ERROR_SUCCESS;
    while (idx < kMaxRunOnceExSubkeys) {
        name_len = kNameBufLen;
        enum_status =
            RegEnumKeyExW(key.get(), idx, name_buf, &name_len, nullptr, nullptr, nullptr, nullptr);
        if (enum_status != ERROR_SUCCESS) break;
        const std::wstring numbered_w(name_buf, name_len);
        ++idx;

        RegKey sub;
        const LSTATUS sub_status = RegOpenKeyExW(key.get(), numbered_w.c_str(), 0, KEY_READ, sub.put());
        if (sub_status != ERROR_SUCCESS) {
            if (!is_benign_absent_reg(sub_status))
                note_constraint(outcome, reg_open_constraint_token(sub_status));
            continue;
        }
        collect_reg_values(sub.get(), location_prefix + L"\\" + numbered_w, id, scope, "-", outcome);
    }
    if (idx >= kMaxRunOnceExSubkeys) {
        // A capped enumeration is not a complete one (AC4) -- probe one
        // more index past the cap; only note row_cap if a real subkey was
        // there. name_len must be reset to the buffer's full capacity
        // first -- RegEnumKeyExW's lpcchName is an in/out param, so it
        // still holds the LAST successful call's returned (possibly
        // shorter) name length, which could turn a real next subkey's
        // longer name into a false ERROR_MORE_DATA this probe must still
        // recognize as proof a subkey is there, not silent completion.
        name_len = kNameBufLen;
        const LSTATUS probe_status =
            RegEnumKeyExW(key.get(), idx, name_buf, &name_len, nullptr, nullptr, nullptr, nullptr);
        if (probe_status == ERROR_SUCCESS || probe_status == ERROR_MORE_DATA)
            note_constraint(outcome, "row_cap");
    } else if (enum_status != ERROR_NO_MORE_ITEMS) {
        // The enumeration stopped before genuinely finishing (ERROR_NO_MORE_
        // ITEMS) and before hitting the cap -- e.g. ERROR_MORE_DATA (a
        // subkey name exceeded the fixed buffer) or another registry error.
        // A real constraint, not silent completion.
        note_constraint(outcome, reg_open_constraint_token(enum_status));
    }
}

void collect_hklm_run_family(std::string_view filter, SourceOutcome& run, SourceOutcome& runonce,
                             SourceOutcome& runonceex) {
    struct Entry {
        SourceId id;
        SourceOutcome* outcome;
        const wchar_t* subkey;
    };
    const Entry entries[] = {
        {SourceId::win_run_hklm, &run, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"},
        {SourceId::win_runonce_hklm, &runonce,
         L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"},
        {SourceId::win_runonceex_hklm, &runonceex,
         L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx"},
    };
    for (const auto& e : entries) {
        if (!want(filter, e.id)) continue;
        const std::wstring native_loc = L"HKLM\\" + std::wstring{e.subkey};
        open_and_collect(HKEY_LOCAL_MACHINE, e.subkey, KEY_WOW64_64KEY, e.id, native_loc,
                         Scope::system, "-", *e.outcome);
        const std::wstring wow_loc = native_loc + L" [WOW6432Node]";
        open_and_collect(HKEY_LOCAL_MACHINE, e.subkey, KEY_WOW64_32KEY, e.id, wow_loc,
                         Scope::system, "-", *e.outcome);
        if (e.id == SourceId::win_runonceex_hklm) {
            collect_runonceex_subkeys(HKEY_LOCAL_MACHINE, e.subkey, KEY_WOW64_64KEY, e.id,
                                      native_loc, Scope::system, *e.outcome);
            collect_runonceex_subkeys(HKEY_LOCAL_MACHINE, e.subkey, KEY_WOW64_32KEY, e.id,
                                      wow_loc, Scope::system, *e.outcome);
        }
    }
}

// ── 2. Explorer StartupApproved\{Run,Run32,StartupFolder} ────────────────

void collect_startup_approved_subkey(HKEY root, const wchar_t* subkey, const std::wstring& label,
                                     Scope scope, std::string_view user,
                                     std::map<std::string, bool>& seen, SourceOutcome& outcome) {
    RegKey key;
    const LSTATUS status = RegOpenKeyExW(root, subkey, 0, KEY_READ, key.put());
    if (status != ERROR_SUCCESS) {
        if (!is_benign_absent_reg(status)) note_constraint(outcome, reg_open_constraint_token(status));
        return;
    }
    auto names = yuzu::win::enumerate_value_names(key.get());
    if (!names.complete) note_constraint(outcome, "enumeration_incomplete");
    const std::int64_t mtime = reg_key_mtime(key.get());
    for (const auto& name : names.names) {
        if (seen.count(name)) continue; // joined by value name -- first subkey wins
        seen[name] = true;
        std::string value, type_name;
        const auto st = yuzu::win::read_reg_value(key.get(), name, value, type_name);
        if (st == ReadValueStatus::not_found) continue;

        Row row;
        row.source_id = SourceId::win_startup_approved;
        row.catalog_version = kAutorunSourceCatalogVersion;
        row.location = wstring_to_utf8(label);
        row.entry = name;
        row.scope = scope;
        row.user = std::string{user};
        row.signed_state = Signed::not_checked;
        row.mtime = mtime;
        if (st == ReadValueStatus::ok) {
            const auto bytes = hex_decode(value);
            row.enabled = parse_startup_approved_blob(
                std::span<const unsigned char>(bytes.data(), bytes.size()));
        } else {
            row.enabled = Enabled::unmodelled;
            note_constraint(outcome, read_status_token(st));
        }
        outcome.rows.push_back(std::move(row));
    }
}

void collect_startup_approved_hive(HKEY root, const std::wstring& base_label, Scope scope,
                                   std::string_view user, SourceOutcome& outcome) {
    std::map<std::string, bool> seen;
    collect_startup_approved_subkey(
        root, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run",
        base_label + L"\\Run", scope, user, seen, outcome);
    collect_startup_approved_subkey(
        root, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run32",
        base_label + L"\\Run32", scope, user, seen, outcome);
    collect_startup_approved_subkey(
        root,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\StartupFolder",
        base_label + L"\\StartupFolder", scope, user, seen, outcome);
}

// ── 3. Winlogon Shell / Userinit ─────────────────────────────────────────

void collect_winlogon(std::string_view filter, SourceOutcome& shell_out,
                     SourceOutcome& userinit_out) {
    struct Entry {
        SourceId id;
        SourceOutcome* outcome;
        const wchar_t* value_name;
        WinlogonValue (*parse)(std::string_view);
    };
    const Entry entries[] = {
        {SourceId::win_winlogon_shell, &shell_out, L"Shell", &parse_winlogon_shell},
        {SourceId::win_winlogon_userinit, &userinit_out, L"Userinit", &parse_winlogon_userinit},
    };
    RegKey key;
    const LSTATUS open_status =
        RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                     L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, KEY_READ,
                     key.put());
    const bool opened = open_status == ERROR_SUCCESS;
    const bool open_constrained = !opened && !is_benign_absent_reg(open_status);
    const std::int64_t mtime = opened ? reg_key_mtime(key.get()) : 0;
    for (const auto& e : entries) {
        if (!want(filter, e.id)) continue;
        if (!opened) {
            if (open_constrained) note_constraint(*e.outcome, reg_open_constraint_token(open_status));
            continue;
        }
        std::string value, type_name;
        const auto st = yuzu::win::read_reg_value(key.get(), yuzu::win::from_wide(e.value_name),
                                                  value, type_name);
        if (st == ReadValueStatus::not_found) continue;

        Row row;
        row.source_id = e.id;
        row.catalog_version = kAutorunSourceCatalogVersion;
        row.location = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
        row.entry = yuzu::win::from_wide(e.value_name);
        row.scope = Scope::system;
        row.user = "-";
        row.signed_state = Signed::not_checked;
        row.mtime = mtime;
        if (st == ReadValueStatus::ok) {
            const auto parsed = e.parse(value);
            if (!parsed.entries.empty()) {
                row.target = parsed.entries.front();
                std::string extra;
                for (std::size_t i = 1; i < parsed.entries.size(); ++i) {
                    if (i > 1) extra += ',';
                    extra += parsed.entries[i];
                }
                row.args = extra;
            }
            row.enabled = Enabled::unknown; // no on/off state; target carries the real signal
        } else {
            row.enabled = Enabled::unmodelled;
            note_constraint(*e.outcome, read_status_token(st));
        }
        e.outcome->rows.push_back(std::move(row));
    }
}

// ── 4. AppInit_DLLs ───────────────────────────────────────────────────────

/// One WOW64 view of AppInit_DLLs. `wow_view` combined with `KEY_READ` selects
/// the 64-bit or 32-bit registry redirection (this key IS subject to WOW64
/// redirection under HKLM\SOFTWARE -- unlike StartupApproved\Run32, which is
/// Explorer's own non-redirected key name); `location` is the row/constraint
/// label for that view, matching collect_hklm_run_family's `[WOW6432Node]`
/// suffix convention.
void collect_appinit_dlls_view(REGSAM wow_view, const std::string& location,
                               SourceOutcome& outcome) {
    RegKey key;
    const LSTATUS status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", 0,
        KEY_READ | wow_view, key.put());
    if (status != ERROR_SUCCESS) {
        if (!is_benign_absent_reg(status)) note_constraint(outcome, reg_open_constraint_token(status));
        return;
    }
    const std::int64_t mtime = reg_key_mtime(key.get());

    std::string load_value, load_type;
    const auto load_st = yuzu::win::read_reg_value(key.get(), "LoadAppInit_DLLs", load_value, load_type);
    Enabled toggle = Enabled::unknown;
    if (load_st == ReadValueStatus::ok) {
        toggle = (load_value == "0") ? Enabled::disabled : Enabled::enabled;
    } else if (load_st != ReadValueStatus::not_found) {
        note_constraint(outcome, read_status_token(load_st));
    }

    std::string dlls_value, dlls_type;
    const auto dlls_st = yuzu::win::read_reg_value(key.get(), "AppInit_DLLs", dlls_value, dlls_type);
    if (dlls_st == ReadValueStatus::not_found) return; // genuinely absent -- 0 rows, supported
    if (dlls_st != ReadValueStatus::ok) {
        note_constraint(outcome, read_status_token(dlls_st));
        Row row;
        row.source_id = SourceId::win_appinit_dlls;
        row.catalog_version = kAutorunSourceCatalogVersion;
        row.location = location;
        row.entry = "AppInit_DLLs";
        row.enabled = Enabled::unmodelled;
        row.scope = Scope::system;
        row.user = "-";
        row.signed_state = Signed::not_checked;
        row.mtime = mtime;
        outcome.rows.push_back(std::move(row));
        return;
    }
    for (const auto& dll : parse_appinit_dlls(dlls_value)) {
        Row row;
        row.source_id = SourceId::win_appinit_dlls;
        row.catalog_version = kAutorunSourceCatalogVersion;
        row.location = location;
        row.entry = "AppInit_DLLs";
        row.target = dll;
        row.enabled = toggle;
        row.scope = Scope::system;
        row.user = "-";
        row.signed_state = Signed::not_checked;
        row.mtime = mtime;
        outcome.rows.push_back(std::move(row));
    }
}

void collect_appinit_dlls(std::string_view filter, SourceOutcome& outcome) {
    if (!want(filter, SourceId::win_appinit_dlls)) return;
    collect_appinit_dlls_view(KEY_WOW64_64KEY,
                              "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                              outcome);
    collect_appinit_dlls_view(
        KEY_WOW64_32KEY,
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows [WOW6432Node]", outcome);
}

// ── 5. Image File Execution Options\*\Debugger ───────────────────────────

constexpr DWORD kMaxIfeoSubkeys = 4096;

void collect_ifeo(std::string_view filter, SourceOutcome& outcome) {
    if (!want(filter, SourceId::win_ifeo_debugger)) return;
    RegKey key;
    const LSTATUS status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", 0,
        KEY_READ, key.put());
    if (status != ERROR_SUCCESS) {
        if (!is_benign_absent_reg(status)) note_constraint(outcome, reg_open_constraint_token(status));
        return;
    }

    constexpr DWORD kNameBufLen = 512;
    wchar_t name_buf[kNameBufLen]{};
    DWORD idx = 0;
    DWORD name_len = kNameBufLen;
    LSTATUS enum_status = ERROR_SUCCESS;
    while (idx < kMaxIfeoSubkeys) {
        name_len = kNameBufLen;
        enum_status =
            RegEnumKeyExW(key.get(), idx, name_buf, &name_len, nullptr, nullptr, nullptr, nullptr);
        if (enum_status != ERROR_SUCCESS) break;
        const std::wstring exe_name_w(name_buf, name_len);
        const std::string exe_name = wstring_to_utf8(exe_name_w);
        ++idx;

        RegKey sub;
        const LSTATUS sub_status = RegOpenKeyExW(key.get(), exe_name_w.c_str(), 0, KEY_READ, sub.put());
        if (sub_status != ERROR_SUCCESS) {
            if (!is_benign_absent_reg(sub_status))
                note_constraint(outcome, reg_open_constraint_token(sub_status));
            continue;
        }
        std::string debugger_value, type_name;
        const auto st = yuzu::win::read_reg_value(sub.get(), "Debugger", debugger_value, type_name);
        if (st == ReadValueStatus::not_found) continue;

        Row row;
        row.source_id = SourceId::win_ifeo_debugger;
        row.catalog_version = kAutorunSourceCatalogVersion;
        row.location =
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution "
            "Options\\" +
            exe_name;
        row.entry = exe_name;
        row.scope = Scope::system;
        row.user = "-";
        row.signed_state = Signed::not_checked;
        row.mtime = reg_key_mtime(sub.get());
        if (st == ReadValueStatus::ok) {
            const auto entry = parse_ifeo_debugger(exe_name, debugger_value);
            if (!entry.has_debugger) continue; // no override present -- not a persistence row
            row.target = entry.debugger;
            row.enabled = Enabled::enabled; // presence of a Debugger override is always active
        } else {
            row.enabled = Enabled::unmodelled;
            note_constraint(outcome, read_status_token(st));
        }
        outcome.rows.push_back(std::move(row));
    }
    if (idx >= kMaxIfeoSubkeys) {
        // A capped enumeration is not a complete one (AC4) -- probe one
        // more index past the cap; only note row_cap if a real subkey was
        // there. name_len must be reset first -- see the identical comment
        // in collect_runonceex_subkeys for why (RegEnumKeyExW's lpcchName
        // in/out reuse otherwise turns a longer next name into a false
        // ERROR_MORE_DATA this probe must still catch).
        name_len = kNameBufLen;
        const LSTATUS probe_status =
            RegEnumKeyExW(key.get(), idx, name_buf, &name_len, nullptr, nullptr, nullptr, nullptr);
        if (probe_status == ERROR_SUCCESS || probe_status == ERROR_MORE_DATA)
            note_constraint(outcome, "row_cap");
    } else if (enum_status != ERROR_NO_MORE_ITEMS) {
        // The enumeration stopped before genuinely finishing and before
        // hitting the cap -- a real registry error, not silent completion.
        note_constraint(outcome, reg_open_constraint_token(enum_status));
    }
}

// ── 6. Startup folders (common + per-user) ───────────────────────────────

constexpr std::size_t kMaxStartupFolderEntries = 1024;

/// RAII owner for a FindFirstFileW search handle: closes via FindClose on
/// every exit path, including a throwing allocation (wstring/vector) inside
/// the enumeration loop -- a bare local HANDLE with FindClose only reached
/// at normal loop exit leaks the handle if anything in the loop body
/// throws. INVALID_HANDLE_VALUE (not nullptr) is FindFirstFileW's failure
/// sentinel. Local to this file, matching filesystem_posture_win.cpp's
/// ScopedVolumeFindHandle (same shape, different closer: FindVolumeClose
/// there, FindClose here).
class ScopedFindHandle {
public:
    explicit ScopedFindHandle(HANDLE h) noexcept : h_(h) {}
    ~ScopedFindHandle() {
        if (valid()) FindClose(h_);
    }
    ScopedFindHandle(const ScopedFindHandle&) = delete;
    ScopedFindHandle& operator=(const ScopedFindHandle&) = delete;
    [[nodiscard]] HANDLE get() const noexcept { return h_; }
    [[nodiscard]] bool valid() const noexcept { return h_ != nullptr && h_ != INVALID_HANDLE_VALUE; }

private:
    HANDLE h_ = INVALID_HANDLE_VALUE;
};

void collect_startup_folder(const std::wstring& dir, SourceId id, Scope scope,
                           std::string_view user, SourceOutcome& outcome) {
    WIN32_FIND_DATAW find_data{};
    const std::wstring pattern = dir + L"\\*";
    const ScopedFindHandle find(FindFirstFileW(pattern.c_str(), &find_data));
    if (!find.valid()) {
        const DWORD err = GetLastError();
        // A genuinely-absent folder is not an error; anything else (access
        // denied foremost) is a real constraint (AC4: failure != empty).
        if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND) {
            note_constraint(outcome, err == ERROR_ACCESS_DENIED ? "permission_denied" : "dir_open_failed");
        }
        return;
    }
    std::size_t count = 0;
    bool capped = false;
    do {
        const std::wstring name = find_data.cFileName;
        if (name == L"." || name == L"..") continue;
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (count >= kMaxStartupFolderEntries) {
            note_constraint(outcome, "row_cap");
            capped = true;
            break;
        }
        Row row;
        row.source_id = id;
        row.catalog_version = kAutorunSourceCatalogVersion;
        row.location = wstring_to_utf8(dir);
        row.entry = wstring_to_utf8(name);
        // .lnk shell-link targets are not resolved -- target/args stay empty.
        row.enabled = Enabled::enabled; // presence in a Startup folder always runs at logon
        row.scope = scope;
        row.user = std::string{user};
        row.signed_state = Signed::not_checked;
        row.mtime = filetime_to_unix(find_data.ftLastWriteTime);
        outcome.rows.push_back(std::move(row));
        ++count;
    } while (FindNextFileW(find.get(), &find_data));
    // FindNextFileW returning FALSE means either a clean end of the listing
    // (GetLastError()==ERROR_NO_MORE_FILES) or a real I/O error partway
    // through -- indistinguishable from the loop-exit condition alone, and
    // a real error must not be silently reported as a complete listing.
    // Only meaningful when the loop ended via that FALSE return, not via the
    // row_cap break above -- GetLastError() after a successful FindNextFileW
    // call is unspecified, so checking it post-break would be a false read.
    if (!capped) {
        if (const DWORD err = GetLastError(); err != ERROR_NO_MORE_FILES)
            note_constraint(outcome, "enumeration_error");
    }
}

// ── 7. Scheduled Tasks (ITaskService) ────────────────────────────────────

constexpr std::size_t kMaxScheduledTasks = 10000;

std::string hr_token(HRESULT hr) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out = "hr_0x";
    for (int shift = 28; shift >= 0; shift -= 4)
        out += kHex[(static_cast<unsigned long>(hr) >> shift) & 0xF];
    return out;
}

/// RAII owner for a BSTR returned by an out-parameter (e.g. IRegisteredTask::
/// get_Path/get_Xml), so the allocation is freed on every exit path --
/// including a throwing conversion between the accessor call and the manual
/// SysFreeString that used to follow it. Local to this file for the same
/// reason agents/plugins/windows_updates/src/windows_updates_plugin.cpp's
/// identical BStrGuard is: agents/shared/win_com.hpp's BStr only allocates
/// (SysAllocString), it has no adopt-an-existing-BSTR constructor.
using BStrGuard = std::unique_ptr<std::remove_pointer_t<BSTR>, decltype(&::SysFreeString)>;

/// Same rationale as BStrGuard, for a PWSTR returned by SHGetKnownFolderPath
/// -- CoTaskMemFree is the required deallocator, never SysFreeString/delete.
using CoTaskMemGuard = std::unique_ptr<std::remove_pointer_t<PWSTR>, decltype(&::CoTaskMemFree)>;

// Defensive bound on folder-tree NESTING DEPTH, independent of row count --
// `cap` alone does not bound recursion: an all-empty folder chain never
// grows `outcome.rows`, so a pathological deeply-nested folder tree (or a
// COM implementation that misreports GetFolders) could recurse until stack
// exhaustion with the row cap never triggering. Real Task Scheduler
// hierarchies are a handful of levels deep, so this is a generous ceiling,
// not a realistic one.
constexpr std::size_t kMaxScheduledTaskFolderDepth = 256;

void walk_task_folder(ITaskFolder* folder, SourceOutcome& outcome, std::size_t cap,
                      std::size_t depth = 0) {
    if (outcome.rows.size() >= cap) {
        // Entered (directly or recursively for a sibling/subfolder) after an
        // earlier folder's own loop already reached the cap exactly at its
        // last item -- that loop's own iteration never re-checks the cap, so
        // this entry-guard is the only place that would otherwise silently
        // drop the rest of the tree with no row_cap recorded.
        note_constraint(outcome, "row_cap");
        return;
    }
    if (depth >= kMaxScheduledTaskFolderDepth) {
        note_constraint(outcome, "row_cap");
        return;
    }

    yuzu::shared::win::ComPtr<IRegisteredTaskCollection> tasks;
    const HRESULT tasks_hr = folder->GetTasks(TASK_ENUM_HIDDEN, tasks.put());
    if (FAILED(tasks_hr)) {
        note_constraint(outcome, hr_token(tasks_hr));
    } else if (tasks) {
        LONG count = 0;
        const HRESULT count_hr = tasks->get_Count(&count);
        if (FAILED(count_hr)) note_constraint(outcome, hr_token(count_hr));
        for (LONG i = 1; i <= count; ++i) {
            if (outcome.rows.size() >= cap) {
                note_constraint(outcome, "row_cap");
                return;
            }
            VARIANT idx;
            VariantInit(&idx);
            idx.vt = VT_I4;
            idx.lVal = i;
            yuzu::shared::win::ComPtr<IRegisteredTask> task;
            const HRESULT item_hr = tasks->get_Item(idx, task.put());
            if (FAILED(item_hr) || !task) {
                note_constraint(outcome, FAILED(item_hr) ? hr_token(item_hr) : "null_task");
                continue;
            }

            BSTR path_raw = nullptr;
            const HRESULT path_hr = task->get_Path(&path_raw);
            BStrGuard path_b(path_raw, &::SysFreeString);
            if (FAILED(path_hr)) note_constraint(outcome, hr_token(path_hr));

            VARIANT_BOOL enabled_b = VARIANT_TRUE;
            const HRESULT enabled_hr = task->get_Enabled(&enabled_b);
            if (FAILED(enabled_hr)) note_constraint(outcome, hr_token(enabled_hr));

            BSTR xml_raw = nullptr;
            const HRESULT xml_hr = task->get_Xml(&xml_raw);
            BStrGuard xml_b(xml_raw, &::SysFreeString);
            if (FAILED(xml_hr)) note_constraint(outcome, hr_token(xml_hr));

            const std::wstring path_w =
                path_b ? std::wstring(path_b.get(), SysStringLen(path_b.get())) : L"";
            const std::wstring xml_w =
                xml_b ? std::wstring(xml_b.get(), SysStringLen(xml_b.get())) : L"";

            const std::string xml_utf8 = wstring_to_utf8(xml_w);
            const auto info = parse_task_xml(xml_utf8);
            if (info.has_unmodelled_action)
                note_constraint(outcome, "unmodelled_action_type");
            // info.parsed_ok is false for a GENUINE parse failure (truncated/
            // corrupt XML, a rejected DTD, an unexpected root) -- distinct
            // from get_Xml() itself failing (already its own hr_token()
            // constraint below) and distinct from a well-formed task that
            // simply has no triggers/actions (parsed_ok=true, empty lists).
            // Only flag "malformed" when get_Xml() actually succeeded and
            // handed back something parse_task_xml could not make sense of
            // -- a COM failure already has its own, more specific token.
            // task_reject_reason_token (autoruns_parsers.hpp) is a pure
            // function specifically so the reject-reason mapping is unit-
            // tested on every build host, not only reachable through this
            // Windows-only COM call site.
            if (!FAILED(xml_hr) && !info.parsed_ok)
                note_constraint(outcome, task_reject_reason_token(info.reject));

            // <RegistrationInfo>/<Date> is read through the same libxml2
            // tree parse_task_xml already built -- no second raw-text scan
            // over xml_utf8. A raw `content.find("<Date>")` predates the
            // libxml2 migration and is also a comment-injection weakness: a
            // `<Date>` string sitting inside an XML comment ahead of the
            // real element would win a raw scan but is correctly skipped by
            // the element-tree lookup.
            const std::int64_t task_mtime = parse_iso8601_to_epoch(info.registration_date);

            const std::string entry_base = wstring_to_utf8(last_path_component(path_w));
            const std::string location = wstring_to_utf8(path_w);
            const std::string user = info.user_id.empty() ? "-" : info.user_id;
            // scheduled_task_enabled_state (autoruns_parsers.hpp) is a pure
            // function specifically so this decision stays testable on
            // every build host -- this COM call site itself only compiles
            // on Windows. See its own banner for the full reasoning.
            const Enabled enabled_state = scheduled_task_enabled_state(
                !FAILED(enabled_hr), !FAILED(xml_hr), enabled_b == VARIANT_TRUE, info);

            // Task Scheduler executes every <Exec> action in sequence -- one
            // row per action (index-suffixed once there's more than one) so
            // a later action is never silently hidden behind the first.
            // rows_for_task (autoruns_parsers.hpp) is the pure, cross-
            // platform-tested row-shaping logic (#4184); this call site's
            // own job is only the row-count cap.
            for (auto& row : rows_for_task(info, location, entry_base, user, task_mtime,
                                           enabled_state)) {
                // A task admitted just under the cap can still carry several
                // actions (bounded by Task Scheduler's own per-task action
                // limit, so not unbounded) -- re-check per row, not just
                // once per task, so the total row count can't creep past
                // the cap.
                if (outcome.rows.size() >= cap) {
                    note_constraint(outcome, "row_cap");
                    return;
                }
                outcome.rows.push_back(std::move(row));
            }
        }
    }

    yuzu::shared::win::ComPtr<ITaskFolderCollection> subfolders;
    const HRESULT folders_hr = folder->GetFolders(0, subfolders.put());
    if (FAILED(folders_hr)) {
        note_constraint(outcome, hr_token(folders_hr));
        return;
    }
    if (!subfolders) return;
    LONG count = 0;
    const HRESULT count_hr = subfolders->get_Count(&count);
    if (FAILED(count_hr)) note_constraint(outcome, hr_token(count_hr));
    for (LONG i = 1; i <= count; ++i) {
        // Explicit check (not a loop-condition early exit) so a cap reached
        // exactly here -- leaving one or more subfolders unwalked -- is
        // recorded, matching the registry walks' probe-past-cap pattern
        // rather than silently truncating at the boundary.
        if (outcome.rows.size() >= cap) {
            note_constraint(outcome, "row_cap");
            break;
        }
        VARIANT idx;
        VariantInit(&idx);
        idx.vt = VT_I4;
        idx.lVal = i;
        yuzu::shared::win::ComPtr<ITaskFolder> sub;
        const HRESULT sub_hr = subfolders->get_Item(idx, sub.put());
        if (FAILED(sub_hr) || !sub) {
            // A subfolder this call can't resolve means its ENTIRE subtree
            // (recursion is the only path into it) goes unwalked -- a real
            // constraint, not a benign zero-subfolder result.
            note_constraint(outcome, FAILED(sub_hr) ? hr_token(sub_hr) : "null_subfolder");
            continue;
        }
        walk_task_folder(sub.get(), outcome, cap, depth + 1);
    }
}

void collect_scheduled_tasks(std::string_view filter, SourceOutcome& outcome) {
    if (!want(filter, SourceId::win_scheduled_tasks)) return;

    yuzu::shared::win::ComInit com;
    if (!com.ok()) {
        // ComInit::ok() does not surface the real HRESULT -- see file banner.
        note_constraint(outcome, "hr_cominit_failed");
        return;
    }

    yuzu::shared::win::ComPtr<ITaskService> service;
    HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_ITaskService, reinterpret_cast<void**>(service.put()));
    if (FAILED(hr) || !service) {
        note_constraint(outcome, hr_token(hr));
        return;
    }

    VARIANT empty;
    VariantInit(&empty);
    hr = service->Connect(empty, empty, empty, empty);
    if (FAILED(hr)) {
        note_constraint(outcome, hr_token(hr));
        return;
    }

    yuzu::shared::win::ComPtr<ITaskFolder> root;
    yuzu::shared::win::BStr root_path(L"\\");
    hr = service->GetFolder(root_path.get(), root.put());
    if (FAILED(hr) || !root) {
        note_constraint(outcome, hr_token(hr));
        return;
    }

    walk_task_folder(root.get(), outcome, kMaxScheduledTasks);
}

// ── 8. WMI permanent event subscriptions ─────────────────────────────────

// escape_wmi_value/format_wmi_block moved to autoruns_parsers.hpp (the
// portable seam) so their round trip with parse_wmi_subscription_triple is
// directly testable off-Windows -- see that header's banner for why the
// escaping exists at all. yuzu::shared::wmi::WmiRow is a plain
// std::map<std::string, std::string>, so it passes through unchanged.

// Formats one joined binding's three CIM blocks (only THIS binding's filter,
// consumer, and the binding itself -- never the whole enumeration) and
// parses them as a self-contained triple. The consumer block keeps its real
// CIM class when the matched row carries one (`CimClass`, as a live COM
// query's synthesized value or a captured PowerShell one already has);
// otherwise it falls back to the generic `__EventConsumer` label -- either
// way `parse_wmi_subscription_triple` routes it by the substring `Consumer`.
WmiTriple parse_joined_binding(const yuzu::autoruns::WmiJoinedBinding& joined) {
    std::string combined = format_wmi_block("__EventFilter", joined.filter);
    const auto class_it = joined.consumer.find("CimClass");
    const std::string consumer_class =
        class_it != joined.consumer.end() && !class_it->second.empty() ? class_it->second
                                                                        : "__EventConsumer";
    combined += format_wmi_block(consumer_class, joined.consumer);
    combined += format_wmi_block("__FilterToConsumerBinding", joined.binding);
    return parse_wmi_subscription_triple(combined);
}

void collect_wmi_subscriptions(std::string_view filter, SourceOutcome& outcome) {
    if (!want(filter, SourceId::win_wmi_subscriptions)) return;

    const yuzu::shared::wmi::BoundedQueryOptions opts; // defaults; never WBEM_INFINITE
    auto filters =
        yuzu::shared::wmi::run_bounded_wmi_query(L"root\\subscription", L"SELECT * FROM __EventFilter", opts);
    auto consumers = yuzu::shared::wmi::run_bounded_wmi_query(
        L"root\\subscription", L"SELECT * FROM __EventConsumer", opts);
    auto bindings = yuzu::shared::wmi::run_bounded_wmi_query(
        L"root\\subscription", L"SELECT * FROM __FilterToConsumerBinding", opts);

    for (const auto* r : {&filters, &consumers, &bindings}) {
        if (r->error) {
            note_constraint(outcome, *r->error);
            return;
        }
    }
    const bool truncated = filters.truncated || consumers.truncated || bindings.truncated;

    // One row per binding, joined on the Filter/Consumer CIM reference Name
    // -- N bindings must never collapse into one row (P12 respec delta 1).
    const auto joined =
        yuzu::autoruns::join_wmi_bindings(filters.rows, consumers.rows, bindings.rows);
    bool noted_unresolved_ref = false;
    for (const auto& binding : joined) {
        const auto triple = parse_joined_binding(binding);

        Row row;
        row.source_id = SourceId::win_wmi_subscriptions;
        row.catalog_version = kAutorunSourceCatalogVersion;
        row.location = "root\\subscription";
        if (!triple.filter_name.empty()) {
            row.entry = triple.filter_name;
        } else if (!triple.consumer_name.empty()) {
            row.entry = triple.consumer_name;
        } else {
            // Dangling ref: neither side resolved to an enumerated row. A
            // forensic reader must still see the raw reference, never a
            // dropped row.
            const auto filter_ref = binding.binding.find("Filter");
            const auto consumer_ref = binding.binding.find("Consumer");
            if (filter_ref != binding.binding.end()) row.entry = filter_ref->second;
            else if (consumer_ref != binding.binding.end()) row.entry = consumer_ref->second;
        }
        row.target = triple.target;
        row.args = triple.query;
        row.enabled = Enabled::unknown; // no on/off bit on a WMI subscription
        row.scope = Scope::system;
        row.user = "-";
        row.signed_state = Signed::not_checked;
        row.mtime = 0; // no timestamp exposed by these three CIM classes
        outcome.rows.push_back(std::move(row));

        if ((!binding.filter_matched || !binding.consumer_matched) && !noted_unresolved_ref) {
            note_constraint(outcome, "unresolved_ref");
            noted_unresolved_ref = true;
        }
    }
    if (truncated) note_constraint(outcome, "row_cap");
}

} // namespace

// ── entry point ───────────────────────────────────────────────────────────

int collect_windows(yuzu::CommandContext& ctx, std::string_view filter) {
    SourceOutcome run_hklm, runonce_hklm, runonceex_hklm;
    collect_hklm_run_family(filter, run_hklm, runonce_hklm, runonceex_hklm);

    SourceOutcome run_hku, runonce_hku;
    SourceOutcome startup_approved;
    if (want(filter, SourceId::win_startup_approved))
        collect_startup_approved_hive(HKEY_LOCAL_MACHINE, L"HKLM", Scope::system, "-",
                                     startup_approved);

    SourceOutcome winlogon_shell, winlogon_userinit;
    collect_winlogon(filter, winlogon_shell, winlogon_userinit);

    SourceOutcome appinit;
    collect_appinit_dlls(filter, appinit);

    SourceOutcome ifeo;
    collect_ifeo(filter, ifeo);

    SourceOutcome startup_folder_common, startup_folder_user;
    if (want(filter, SourceId::win_startup_folder_common)) {
        // SHGetKnownFolderPath, not an env-var lookup: %ProgramData% is a
        // process-environment string with no failure signal distinct from
        // "just not set" -- a missing/oversized var or a redirected known
        // folder previously read as a silent supported|0 rather than a
        // flagged constraint.
        PWSTR known_path_raw = nullptr;
        const HRESULT hr =
            SHGetKnownFolderPath(FOLDERID_CommonStartup, 0, nullptr, &known_path_raw);
        CoTaskMemGuard known_path(known_path_raw, &::CoTaskMemFree);
        if (SUCCEEDED(hr) && known_path) {
            collect_startup_folder(std::wstring(known_path.get()),
                                   SourceId::win_startup_folder_common, Scope::system, "-",
                                   startup_folder_common);
        } else {
            note_constraint(startup_folder_common, hr_token(hr));
        }
    }

    SourceOutcome scheduled_tasks;
    collect_scheduled_tasks(filter, scheduled_tasks);

    SourceOutcome wmi_subscriptions;
    collect_wmi_subscriptions(filter, wmi_subscriptions);

    // ── per-user pass: ProfileList + every reachable HKU hive ────────────
    const bool need_per_user = want(filter, SourceId::win_run_hku) ||
                               want(filter, SourceId::win_runonce_hku) ||
                               want(filter, SourceId::win_startup_approved) ||
                               want(filter, SourceId::win_startup_folder_user);
    if (need_per_user) {
        bool profiles_ok = false;
        bool profiles_truncated = false;
        const auto records =
            yuzu::win::enumerate_profile_records(profiles_ok, &profiles_truncated);
        if (profiles_truncated)
            ctx.write_output(yuzu::profiles::render_profile_list_truncated_warning(
                yuzu::win::kMaxProfiles));

        if (!profiles_ok) {
            for (SourceOutcome* o : {&run_hku, &runonce_hku, &startup_approved,
                                     &startup_folder_user})
                note_constraint(*o, "profile_list_unreadable");
        } else {
            const auto hku_subkeys = yuzu::win::enumerate_hku_subkeys();
            const auto profiles = yuzu::profiles::build_profile_list(records, hku_subkeys);

            for (const auto& profile : profiles) {
                const std::string_view user =
                    profile.profile_name.empty() ? std::string_view{profile.sid}
                                                 : std::string_view{profile.profile_name};

                // Default (non-redirected) Startup folder path -- the common
                // case, and the fallback whenever a registry-declared
                // redirection can't be resolved (hive unreachable, or the
                // value is absent). Computed up front, unconditionally, so
                // the listing below still runs even if with_user_hive fails
                // entirely -- the folder listing has never depended on hive
                // access, and must keep working exactly as before for a
                // logged-out or otherwise hive-unreachable profile.
                std::optional<std::wstring> startup_dir;
                if (want(filter, SourceId::win_startup_folder_user)) {
                    if (!profile.profile_path.empty()) {
                        startup_dir = yuzu::win::to_wide(profile.profile_path) +
                                     L"\\AppData\\Roaming\\Microsoft\\Windows\\Start "
                                     L"Menu\\Programs\\Startup";
                    } else if (profile.profile_path_unreadable) {
                        // An unreadable/ACL-denied ProfileImagePath must not
                        // silently drop this profile from a Supported source --
                        // matches the constraint-not-empty-result discipline
                        // every other collector in this file follows.
                        note_constraint(startup_folder_user, "profile_path_unreadable");
                    }
                }

                if (!want(filter, SourceId::win_run_hku) &&
                    !want(filter, SourceId::win_runonce_hku) &&
                    !want(filter, SourceId::win_startup_approved) &&
                    !startup_dir.has_value())
                    continue;

                yuzu::win::HiveAccessReport report;
                const auto status = yuzu::win::with_user_hive(
                    profile.sid, profile.profile_path,
                    [&](HKEY root) {
                        if (startup_dir.has_value()) {
                            // A profile's Startup folder can be redirected via
                            // policy/USER_SHELL_FOLDERS -- resolve it from the
                            // same per-user hive this callback already has
                            // open, rather than trusting the literal
                            // AppData\Roaming suffix unconditionally. Absent,
                            // unreadable, or empty leaves startup_dir at the
                            // fallback already computed above.
                            //
                            // #4219 fix: resolution itself is now
                            // resolve_profile_shell_folder (autoruns_parsers.hpp),
                            // a pure, cross-platform-tested function that
                            // expands %USERPROFILE%-style tokens against THIS
                            // profile's own path/name -- never
                            // ExpandEnvironmentStringsW, which has no notion of
                            // "a different user's profile" and would resolve
                            // against the agent's own LocalSystem environment
                            // (the bug this fix closes; see
                            // changelog.d/20260909-autoruns-plugin.added.md's
                            // former "Known limitation" entry, now removed).
                            RegKey folders_key;
                            const LSTATUS open_st = RegOpenKeyExW(
                                root,
                                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User "
                                L"Shell Folders",
                                0, KEY_READ, folders_key.put());
                            if (open_st != ERROR_SUCCESS) {
                                if (open_st != ERROR_FILE_NOT_FOUND)
                                    note_constraint(startup_folder_user,
                                                    "startup_redirect_key_unreadable");
                            } else {
                                std::string startup_value, type_name;
                                const auto st = yuzu::win::read_reg_value(
                                    folders_key.get(), "Startup", startup_value, type_name);
                                if (st != yuzu::win::ReadValueStatus::not_found &&
                                    st != yuzu::win::ReadValueStatus::ok)
                                    note_constraint(startup_folder_user, read_status_token(st));
                                if (st == yuzu::win::ReadValueStatus::ok) {
                                    const auto resolution = resolve_profile_shell_folder(
                                        startup_value, type_name, profile.profile_path,
                                        std::string{user},
                                        [](std::string_view name) -> std::optional<std::string> {
                                            return win_machine_env_var(name);
                                        });
                                    if (resolution.path.has_value()) {
                                        startup_dir = yuzu::win::to_wide(*resolution.path);
                                    } else if (!resolution.constraint.empty()) {
                                        note_constraint(startup_folder_user,
                                                        resolution.constraint);
                                    }
                                }
                            }
                        }
                        if (want(filter, SourceId::win_run_hku))
                            open_and_collect(root, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                                            0, SourceId::win_run_hku,
                                            L"HKU\\" + yuzu::win::to_wide(profile.sid) + L"\\Run",
                                            Scope::user, user, run_hku);
                        if (want(filter, SourceId::win_runonce_hku))
                            open_and_collect(
                                root, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0,
                                SourceId::win_runonce_hku,
                                L"HKU\\" + yuzu::win::to_wide(profile.sid) + L"\\RunOnce",
                                Scope::user, user, runonce_hku);
                        if (want(filter, SourceId::win_startup_approved))
                            collect_startup_approved_hive(
                                root, L"HKU\\" + yuzu::win::to_wide(profile.sid), Scope::user,
                                user, startup_approved);
                    },
                    &report);

                for (const auto& line : yuzu::profiles::render_hive_access_lines(
                         status, report.unload_failed, report.mount_name, profile.sid))
                    ctx.write_output(line); // unload_failed warnings surfaced, never dropped

                if (status != yuzu::win::HiveAccessStatus::ok) {
                    const std::string token =
                        profile.sid + ":" + std::string{hive_status_token(status)};
                    if (want(filter, SourceId::win_run_hku)) note_constraint(run_hku, token);
                    if (want(filter, SourceId::win_runonce_hku))
                        note_constraint(runonce_hku, token);
                    if (want(filter, SourceId::win_startup_approved))
                        note_constraint(startup_approved, token);
                    // #4219: the redirect-resolution block above lives INSIDE
                    // this same with_user_hive callback -- when the hive is
                    // unreachable, that block never runs at all, so
                    // startup_dir stays at the non-redirected fallback
                    // computed earlier. For a genuinely non-redirected
                    // profile that's still a complete, honest answer; for a
                    // genuinely REDIRECTED one it's an unverifiable guess
                    // (the exact class of silent-wrong-answer #4219 fixes
                    // when the hive IS reachable), so this source gets the
                    // same per-profile constraint the other three hive-
                    // dependent sources already do.
                    if (startup_dir.has_value()) note_constraint(startup_folder_user, token);
                }

                if (startup_dir.has_value()) {
                    collect_startup_folder(*startup_dir, SourceId::win_startup_folder_user,
                                          Scope::user, user, startup_folder_user);
                }
            }
        }
    }

    // Every source's own finish_source_or_filtered result is ORed together
    // below -- true iff ANY source this leg processed resolved to
    // CONSTRAINED -- so collect_windows's return value can surface a real
    // acquisition degradation to do_list's aggregate CC-07 result-status
    // (autoruns_plugin.cpp) instead of it being visible only in this leg's
    // individual `source|` text lines.
    bool any_constrained = false;
    any_constrained |= finish_source_or_filtered(ctx, filter, SourceId::win_run_hklm, run_hklm);
    any_constrained |=
        finish_source_or_filtered(ctx, filter, SourceId::win_runonce_hklm, runonce_hklm);
    any_constrained |=
        finish_source_or_filtered(ctx, filter, SourceId::win_runonceex_hklm, runonceex_hklm);
    any_constrained |= finish_source_or_filtered(ctx, filter, SourceId::win_run_hku, run_hku);
    any_constrained |=
        finish_source_or_filtered(ctx, filter, SourceId::win_runonce_hku, runonce_hku);
    any_constrained |=
        finish_source_or_filtered(ctx, filter, SourceId::win_startup_approved, startup_approved);
    any_constrained |=
        finish_source_or_filtered(ctx, filter, SourceId::win_winlogon_shell, winlogon_shell);
    any_constrained |=
        finish_source_or_filtered(ctx, filter, SourceId::win_winlogon_userinit, winlogon_userinit);
    any_constrained |= finish_source_or_filtered(ctx, filter, SourceId::win_appinit_dlls, appinit);
    any_constrained |= finish_source_or_filtered(ctx, filter, SourceId::win_ifeo_debugger, ifeo);
    any_constrained |= finish_source_or_filtered(ctx, filter, SourceId::win_startup_folder_common,
                                                 startup_folder_common);
    any_constrained |= finish_source_or_filtered(ctx, filter, SourceId::win_startup_folder_user,
                                                 startup_folder_user);
    any_constrained |=
        finish_source_or_filtered(ctx, filter, SourceId::win_scheduled_tasks, scheduled_tasks);
    any_constrained |= finish_source_or_filtered(ctx, filter, SourceId::win_wmi_subscriptions,
                                                 wmi_subscriptions);

    // Non-zero signals "at least one source reported CONSTRAINED" to
    // do_list's aggregate -- distinct from this function's own success/
    // failure, which this leg has no way to report other than an escaping
    // exception (caught in execute()).
    return any_constrained ? 1 : 0;
}

} // namespace yuzu::autoruns

#endif // _WIN32
