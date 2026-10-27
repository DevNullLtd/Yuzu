/**
 * shares_legs.hpp -- shared seam between the shares plugin TU and its three per-OS leg
 * TUs (mgmt_posture_legs.hpp shape). Linux reads CONFIGURED shares from files; Windows
 * reads the LIVE shares through NetShareEnum; the macOS leg is a PLANNED placeholder.
 *
 * Holds (a) the per-OS entry-point declarations, (b) report_list, the SINGLE owner of the
 * `status|list|...` row (no leg and no parser writes one), pairing each status with its
 * result status/completeness, (c) execute_list, the plugin's whole execute() body
 * (dispatch + ABI containment), and (d) the OS-free DECISION logic, `list_linux` and
 * `list_windows`, over injected boundaries (file readers, an exports.d lister, a directory
 * probe; a NetShareEnum page source) so the refused-vs-absent and paging rules are
 * unit-tested with canned results and no disk, uid or Windows dependence. The leg TUs keep
 * only the OS shell.
 *
 * Row contract (pipe rows, status row first):
 *   status|list|<supported|constrained|permission_denied|unsupported>|<tokens or ->
 *   source|<exports|exports_d|smb_conf|netshareenum>|<read|absent|refused|failed>|<n or ->
 *   share|<nfs|smb>|<name>|<path>|<ro|rw|mixed|->|<true|false|->|<flags or ->|<source>
 * One `source` row per source the leg knows about is emitted on EVERY arm, so zero `share`
 * rows is never an ambiguous empty success. Linux rows are CONFIGURED shares, not live
 * nfsd/smbd state; Windows rows are the live Server-service shares. ACLs are never read.
 *
 * Each entry point is a READ and returns 0: a degraded read is not a failed command.
 */
#pragma once

#include "shares_parsers.hpp"

#include <constraint_accumulator.hpp>
#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::shares {

int run_windows(yuzu::CommandContext& ctx);
int run_linux(yuzu::CommandContext& ctx);
int run_macos(yuzu::CommandContext& ctx);

enum class StatusState { supported, constrained, permission_denied, unsupported };

inline std::string_view status_token(StatusState s) {
    switch (s) {
    case StatusState::supported:
        return "supported";
    case StatusState::constrained:
        return "constrained";
    case StatusState::permission_denied:
        return "permission_denied";
    case StatusState::unsupported:
        return "unsupported";
    }
    return "unsupported";
}

inline std::string format_status_row(StatusState s, std::string_view reason) {
    std::string r = "status|list|";
    r += status_token(s);
    r += '|';
    r += reason.empty() ? std::string{"-"} : yuzu::util::safe_output_field(reason);
    return r;
}

/// Writes the status row FIRST, then the data rows, then the paired result status.
/// `unsupported` (a leg that read nothing) pairs with UNAVAILABLE/UNKNOWN; every other
/// state is a read that ran.
inline void report_list(yuzu::CommandContext& ctx, const std::vector<std::string>& data_rows,
                        StatusState status, std::string_view reason) {
    ctx.write_output(format_status_row(status, reason));
    for (const auto& r : data_rows)
        ctx.write_output(r);
    switch (status) {
    case StatusState::permission_denied:
        ctx.set_result_status(YUZU_RESULT_STATUS_PERMISSION_DENIED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              std::string{reason});
        break;
    case StatusState::constrained:
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              std::string{reason});
        break;
    case StatusState::unsupported:
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_UNKNOWN,
                              std::string{reason});
        break;
    case StatusState::supported:
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
        break;
    }
}

/// What a leg decided: the status, its reason token(s), and the data rows.
struct Listing {
    StatusState status = StatusState::supported;
    std::string reason;
    std::vector<std::string> rows;
};

/// A leg that reads nothing reports `{StatusState::unsupported, <token>, rows}`:
/// ONE `unsupported` status row and UNAVAILABLE/UNKNOWN carrying the same token. Callers:
/// the macOS placeholder, list_windows' service-stopped arm (with its failed `source` row)
/// and execute_list's catch arm (`<os>:leg:exception`).
inline void report_list(yuzu::CommandContext& ctx, const Listing& p) {
    report_list(ctx, p.rows, p.status, p.reason);
}

using LegFn = int (*)(yuzu::CommandContext&);

/// The WHOLE body of the plugin's execute(): dispatch and the single ABI containment.
/// Status-row contract: one status row per dispatch, with three exceptions. (1) An unknown
/// action writes ONE non-status line (`unknown action: <name>`, invalid UTF-8 replaced and
/// the rest escaped) and returns 1: no status row. (2) A leg that throws AFTER report_list
/// already wrote its row gets the catch arm's `unsupported` row appended, so there are TWO
/// and the LAST status row wins. (3) The recovery itself allocates, so it is guarded too: if
/// it throws as well, the dispatch returns 1 rather than unwinding across the plugin ABI.
inline int execute_list(yuzu::CommandContext& ctx, std::string_view action, LegFn leg,
                        std::string_view leg_exception_token) {
    try {
        if (action != "list") {
            std::string a{action};
            yuzu::shared::scrub_wire_bytes(a);
            ctx.write_output("unknown action: " + yuzu::util::safe_output_field(a));
            return 1;
        }
        return leg(ctx);
    } catch (...) {
        try {
            report_list(ctx, Listing{StatusState::unsupported, std::string{leg_exception_token}, {}});
        } catch (...) {
            return 1;
        }
        return 0;
    }
}

// ---------------------------------------------------------------------------
// Shared read classification (OS-free)
// ---------------------------------------------------------------------------

enum class ReadErr { none, symlink_refused, not_regular, oversized, io };

/// Mirrors yuzu::shared::FileRead so the decision logic compiles on every OS.
struct FileReadLike {
    std::string data;
    ReadErr error = ReadErr::none;
    int err = 0; ///< errno when error == io
};

using ReadFn = std::function<FileReadLike(const std::string& path)>;

inline bool refused(int err) { return err == EACCES || err == EPERM; }

inline std::string errno_token(int err) {
    switch (err) {
    case ENOENT:
        return "enoent";
    case EACCES:
    case EPERM:
        return "permission_denied";
    case EIO:
        return "eio";
    case ELOOP:
        return "eloop";
    case ENOTDIR:
        return "enotdir";
    case ENAMETOOLONG:
        return "enametoolong";
    default:
        return "errno_" + std::to_string(err);
    }
}

struct SrcOutcome {
    SourceState state = SourceState::absent;
    std::string token; ///< failure/refusal token; empty for read and absent
};

inline std::string src_token(std::string_view os, std::string_view src, std::string_view cause) {
    std::string t{os};
    t += ":shares:";
    t += src;
    t += ':';
    t += cause;
    return t;
}

/// Absent is a state, never a failure; a refusal is its own state; everything else that
/// kept the file from being read, and a NUL byte in what was read, is a failure.
inline SrcOutcome classify_read(const FileReadLike& r, std::string_view os, std::string_view src) {
    switch (r.error) {
    case ReadErr::none:
        if (r.data.find('\0') != std::string::npos)
            return {SourceState::failed, src_token(os, src, "invalid_bytes")};
        return {SourceState::read, {}};
    case ReadErr::symlink_refused:
        return {SourceState::failed, src_token(os, src, "symlink_refused")};
    case ReadErr::not_regular:
        return {SourceState::failed, src_token(os, src, "not_regular")};
    case ReadErr::oversized:
        return {SourceState::failed, src_token(os, src, "oversized")};
    case ReadErr::io:
        if (r.err == ENOENT)
            return {SourceState::absent, {}};
        if (refused(r.err))
            return {SourceState::refused, src_token(os, src, "permission_denied")};
        return {SourceState::failed, src_token(os, src, errno_token(r.err))};
    }
    return {SourceState::failed, src_token(os, src, "unknown")};
}

/// Collects tokens and the data of one listing. `denied` keeps refusal tokens in order;
/// every other token goes through the shared ConstraintAccumulator.
struct Tally {
    yuzu::shared::RowByteBudget budget{kMaxShareRows, kMaxShareBytes};
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<std::string> denied;
    std::vector<Share> shares;
    std::size_t read_sources = 0;
    bool truncated = false;
    bool field_oversized = false;

    void note(const SrcOutcome& o) {
        if (o.state == SourceState::read)
            ++read_sources;
        if (o.token.empty())
            return;
        if (o.state == SourceState::refused) {
            if (std::ranges::find(denied, o.token) == denied.end())
                denied.push_back(o.token);
        } else {
            acc.add_failure(o.token);
        }
    }

    /// Merges any parse result carrying `shares`, `truncated` and `field_oversized`.
    template <class P>
    void take(P& p) {
        truncated = truncated || p.truncated;
        field_oversized = field_oversized || p.field_oversized;
        for (auto& s : p.shares)
            shares.push_back(std::move(s));
    }

    /// Final status: permission_denied only when >=1 source was refused and none was read;
    /// any token -> constrained; else supported.
    Listing finish(std::vector<std::string> source_rows) {
        Listing l;
        l.rows = std::move(source_rows);
        for (const auto& s : shares)
            l.rows.push_back(share_row(s));
        std::string reason;
        for (const auto& t : denied) {
            if (!reason.empty())
                reason += ',';
            reason += t;
        }
        if (acc.any_failure()) {
            if (!reason.empty())
                reason += ',';
            reason += acc.reason();
        }
        l.reason = std::move(reason);
        if (!denied.empty() && read_sources == 0)
            l.status = StatusState::permission_denied;
        else if (!denied.empty() || acc.any_failure())
            l.status = StatusState::constrained;
        else
            l.status = StatusState::supported;
        return l;
    }
};

inline std::optional<std::size_t> count_if_read(SourceState s, std::size_t n) {
    return s == SourceState::read ? std::optional<std::size_t>{n} : std::nullopt;
}

// ---------------------------------------------------------------------------
// Linux decision logic (OS-free; the shell in shares_posix_fs.hpp injects the I/O)
// ---------------------------------------------------------------------------

/// The injected Linux boundaries plus the three paths they serve.
struct LinuxFs {
    std::string exports_path;
    std::string smb_conf_path;
    std::string usershares_default;
    /// Bounded no-follow read of one regular file.
    ReadFn read;
    /// Lists `*.exports` names into `names` (sorted, already cut to the file cap) and sets
    /// `too_many`. Returns 0 or the errno of a failed open/readdir (ENOTDIR for a symlinked
    /// or non-directory exports.d).
    std::function<int(std::vector<std::string>& names, bool& too_many)> list_exports_d;
    /// Reads one listed snippet by name, confined to the directory the listing opened.
    std::function<FileReadLike(const std::string& name)> read_exports_d_file;
    /// lstat-based directory probe: never lists, never follows. 0 = a directory; ENOENT or
    /// ENOTDIR (a symlink or other non-directory) = absent; any other errno = could not tell.
    std::function<int(const std::string& path)> dir_probe;
};

inline Listing list_linux(const LinuxFs& fs) {
    Tally t;

    // --- /etc/exports ---
    FileReadLike r = fs.read(fs.exports_path);
    SrcOutcome o = classify_read(r, "linux", "exports");
    std::size_t n_exports = 0;
    if (o.state == SourceState::read) {
        ExportsParse p;
        parse_exports(r.data, "exports", t.budget, p);
        n_exports = p.shares.size();
        t.take(p);
    }
    t.note(o);
    std::vector<std::string> source_rows;
    source_rows.push_back(source_row("exports", o.state, count_if_read(o.state, n_exports)));

    // --- /etc/exports.d/*.exports ---
    {
        std::vector<std::string> names;
        bool too_many = false;
        const int err = fs.list_exports_d(names, too_many);
        SourceState st = SourceState::absent;
        std::size_t n = 0;
        bool any_read = false; // a snippet was read even if a sibling was refused
        const auto rank = [](SourceState s) {
            switch (s) {
            case SourceState::failed:
                return 3;
            case SourceState::refused:
                return 2;
            case SourceState::read:
                return 1;
            default:
                return 0;
            }
        };
        const auto worsen = [&](SourceState s) {
            if (rank(s) > rank(st))
                st = s;
        };
        if (err == ENOTDIR) {
            st = SourceState::failed;
            t.acc.add_failure("linux:shares:exports_d:not_a_directory");
        } else if (err != 0) {
            // ENOENT -> absent (no token), EACCES/EPERM -> refused, anything else -> failed.
            const SrcOutcome lo = classify_read(FileReadLike{{}, ReadErr::io, err}, "linux", "exports_d");
            st = lo.state;
            t.note(lo);
        } else {
            st = SourceState::read;
            if (too_many)
                t.acc.add_failure("linux:shares:exports_d:too_many");
            for (const auto& name : names) {
                const FileReadLike sr = fs.read_exports_d_file(name);
                const SrcOutcome so = classify_read(sr, "linux", "exports_d");
                if (so.state == SourceState::absent)
                    continue; // vanished between listing and read: a snapshot of a changing dir
                if (so.state == SourceState::read) {
                    any_read = true;
                    ExportsParse p;
                    parse_exports(sr.data, "exports_d", t.budget, p);
                    n += p.shares.size();
                    t.take(p);
                } else {
                    t.note(so);
                }
                worsen(so.state);
            }
        }
        if (st == SourceState::read || any_read)
            ++t.read_sources;
        source_rows.push_back(source_row("exports_d", st, count_if_read(st, n)));
    }

    // --- /etc/samba/smb.conf ---
    r = fs.read(fs.smb_conf_path);
    o = classify_read(r, "linux", "smb_conf");
    std::size_t n_smb = 0;
    if (o.state == SourceState::read) {
        auto conf = parse_smb_conf(r.data, t.budget);
        n_smb = conf.shares.size();
        if (conf.registry_backend)
            t.acc.add_failure("linux:shares:smb_conf:registry_backend");
        if (conf.include_present)
            t.acc.add_failure("linux:shares:smb_conf:include_unresolved");
        if (conf.copy_unresolved)
            t.acc.add_failure("linux:shares:smb_conf:copy_unresolved");
        // Usershares are never listed. Configured in the file -> token, no probe; explicitly
        // disabled (`usershare max shares = 0`) -> neither. Otherwise a Debian build's
        // compiled-in default is invisible in the file, so the default directory is the
        // evidence, and a probe that could not tell is reported, never read as absent.
        if (conf.usershares_configured) {
            t.acc.add_failure("linux:shares:smb_conf:usershares_not_read");
        } else if (!conf.usershares_off) {
            const int pe = fs.dir_probe(fs.usershares_default);
            if (pe == 0)
                t.acc.add_failure("linux:shares:smb_conf:usershares_not_read");
            else if (pe != ENOENT && pe != ENOTDIR)
                t.acc.add_failure("linux:shares:smb_conf:usershares_unreadable");
        }
        t.take(conf);
    }
    t.note(o);
    source_rows.push_back(source_row("smb_conf", o.state, count_if_read(o.state, n_smb)));

    if (t.truncated)
        t.acc.add_failure("linux:shares:row_cap");
    if (t.field_oversized)
        t.acc.add_failure("linux:shares:field_oversized");
    return t.finish(std::move(source_rows));
}

// ---------------------------------------------------------------------------
// Windows decision logic (OS-free; the shell in shares_win.cpp injects NetShareEnum)
// ---------------------------------------------------------------------------

/// One NetShareEnum entry, already converted to UTF-8 by the shell. No `remark` (free text
/// that can name people) and no ACL: names, paths and the type word only.
struct WinShareRec {
    std::string name;
    std::string path; ///< empty at level 1 (SHARE_INFO_1 carries none) and for IPC$
    std::uint32_t type = 0; ///< SHARE_INFO_*.shi*_type
};

/// One NetShareEnum call: its NET_API_STATUS and the entries of THAT page only.
struct WinPage {
    std::uint32_t status = 0;
    std::vector<WinShareRec> shares;
};

/// Successive calls at one level return successive pages. The shell owns the resume handle
/// and resets it when the level changes.
using WinPageFn = std::function<WinPage(int level)>;

// lmshare.h STYPE_*, lmerr.h / winerror.h codes. shares_win.cpp static_asserts these against
// the SDK; they live here so the portable tests can name them.
inline constexpr std::uint32_t kStypeMask = 0xFF; ///< STYPE_MASK: the low byte is the kind
inline constexpr std::uint32_t kStypeSpecial = 0x80000000u;   ///< STYPE_SPECIAL (ADMIN$, C$, IPC$)
inline constexpr std::uint32_t kStypeTemporary = 0x40000000u; ///< STYPE_TEMPORARY
inline constexpr std::uint32_t kWinAccessDenied = 5;          ///< ERROR_ACCESS_DENIED
inline constexpr std::uint32_t kWinMoreData = 234;            ///< ERROR_MORE_DATA
inline constexpr std::uint32_t kNerrServerNotStarted = 2114;  ///< NERR_ServerNotStarted
inline constexpr std::uint32_t kRpcServerUnavailable = 1722;  ///< RPC_S_SERVER_UNAVAILABLE
inline constexpr std::uint32_t kRpcUnknownIf = 1717;          ///< RPC_S_UNKNOWN_IF

/// Level 2 first; ERROR_ACCESS_DENIED at level 2 discards what was gathered and retries
/// level 1 (names, no paths) as `constrained`. A stopped Server service is typed
/// `unsupported`, never an empty list. Any other status on any page discards every row (a
/// partial drain is never reported as a complete list).
///
/// Termination without a page counter: every entry of a non-empty page charges the row/byte
/// budget BEFORE a Share is built, and the first refusal stops paging, so a pager that keeps
/// answering ERROR_MORE_DATA with rows (a cyclic cursor) is cut at kMaxShareRows retained
/// entries; an empty ERROR_MORE_DATA page is `no_progress` and stops at once.
inline Listing list_windows(const WinPageFn& page) {
    constexpr std::string_view kOs = "windows";
    constexpr std::string_view kSrc = "netshareenum";
    const auto tok = [&](std::string_view cause) { return src_token(kOs, kSrc, cause); };
    const auto failed_src = [&] { return source_row(kSrc, SourceState::failed); };

    Tally t;
    std::vector<Share> got;
    int level = 2;
    bool level2_denied = false;
    bool failed = false;

    for (;;) {
        const WinPage p = page(level);

        if (p.status == kWinAccessDenied) {
            got.clear();
            if (level == 2) {
                level = 1;
                level2_denied = true;
                t.budget.reset(); // the discarded level-2 rows no longer count
                t.field_oversized = false;
                continue;
            }
            t.note({SourceState::refused, tok("permission_denied")});
            return t.finish({source_row(kSrc, SourceState::refused)});
        }
        if (p.status == kNerrServerNotStarted)
            return Listing{StatusState::unsupported, tok("server_not_started"), {failed_src()}};
        if (p.status == kRpcServerUnavailable || p.status == kRpcUnknownIf)
            return Listing{StatusState::unsupported, tok("server_unavailable"), {failed_src()}};
        if (p.status != 0 && p.status != kWinMoreData) {
            t.acc.add_failure(tok("status_" + std::to_string(p.status)));
            failed = true;
            break;
        }

        for (const auto& rec : p.shares) {
            static constexpr std::array<std::string_view, 4> kKinds{"disk", "print", "device",
                                                                    "ipc"};
            const auto kind = rec.type & kStypeMask;
            std::vector<std::string> flags;
            flags.emplace_back(kind < kKinds.size() ? kKinds[kind] : "other");
            if ((rec.type & kStypeSpecial) != 0)
                flags.emplace_back("special");
            if ((rec.type & kStypeTemporary) != 0)
                flags.emplace_back("temporary");
            if (!detail::charge_share(t.budget, rec.name.size(),
                                      rec.path.empty() ? 1 : rec.path.size(),
                                      detail::flags_bytes(flags))) {
                t.truncated = true;
                break;
            }
            Share s;
            s.proto = Proto::smb;
            s.name = detail::cut(rec.name, t.field_oversized);
            s.path = detail::cut(rec.path, t.field_oversized);
            s.flags = std::move(flags);
            s.source = std::string{kSrc};
            got.push_back(std::move(s));
        }
        if (t.truncated || p.status == 0)
            break;
        if (p.shares.empty()) { // ERROR_MORE_DATA that read nothing: no forward progress
            t.acc.add_failure(tok("no_progress"));
            failed = true;
            break;
        }
    }

    if (level2_denied)
        t.acc.add_failure(tok("level2_permission_denied"));
    if (failed) // no rows survive a failed drain
        return t.finish({failed_src()});
    ++t.read_sources;
    const std::size_t n = got.size();
    t.shares = std::move(got);
    if (t.truncated)
        t.acc.add_failure("windows:shares:row_cap");
    if (t.field_oversized)
        t.acc.add_failure("windows:shares:field_oversized");
    return t.finish({source_row(kSrc, SourceState::read, n)});
}

} // namespace yuzu::shares
