/**
 * remote_access_audit_legs.hpp -- shared seam between the remote_access_audit plugin TU and
 * its three per-OS leg TUs (shares_legs.hpp / mgmt_posture_legs.hpp shape). Linux and macOS
 * are real legs over the SAME POSIX decision logic; Windows is a PLANNED placeholder.
 *
 * Holds the per-OS entry points, report_list (the SINGLE owner of the `status|list|...` row),
 * execute_list (the plugin's whole execute() body: dispatch + ABI containment) and the OS-free
 * decision logic, `list_posix`, over an injected `PosixFs` boundary so every refused-vs-absent,
 * budget and ordering rule is unit-tested with canned results. The leg TUs keep only the OS
 * shell. list_posix takes the run-start network mount snapshot ONCE, before any path is touched.
 *
 * Row contract (pipe rows, status row first):
 *   status|list|<supported|constrained|permission_denied|unsupported>|<tokens or ->
 *   source|<sshd_config|homes|service>|<read|absent|refused|failed>|<n or ->[|<skipped or ->]
 *   config|<key>|<value or ->|<origin or ->
 *   service|<unit>|<state>|<mechanism>
 *   file|<account>|<authorized_keys|authorized_keys2|custom>|<read|absent|refused|failed>|<keys>|<malformed>|<oversized>
 *   key|<account>|<kind>|<type>|<SHA256:...>|<bits or ->|<flags or ->|<option names or ->
 * `account` is the HOME DIRECTORY BASENAME, not the login name. All rows are CONFIGURED facts,
 * not sshd's effective policy. Each entry point is a READ and returns 0.
 */
#pragma once

#include "remote_access_audit_config_parsers.hpp"
#include "remote_access_audit_keys_parsers.hpp"

#include <constraint_accumulator.hpp>
#include <yuzu/agent/runner_status.hpp>
#include <yuzu/agent/subprocess_runner.hpp>
#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::remote_access_audit {

int run_windows(yuzu::CommandContext& ctx);
int run_linux(yuzu::CommandContext& ctx);
int run_macos(yuzu::CommandContext& ctx);

enum class StatusState { supported, constrained, permission_denied, unsupported };

/// Writes the status row FIRST, then the data rows, then the paired result status.
/// `unsupported` (a leg that read nothing) pairs with UNAVAILABLE/UNKNOWN; every other
/// state is a read that ran.
inline void report_list(yuzu::CommandContext& ctx, const std::vector<std::string>& data_rows,
                        StatusState status, std::string_view reason) {
    struct Pairing {
        std::string_view token;
        YuzuResultStatus status;
        YuzuResultCompleteness completeness;
    };
    // Indexed by StatusState.
    static constexpr std::array<Pairing, 4> kPairing{{
        {"supported", YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL},
        {"constrained", YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL},
        {"permission_denied", YUZU_RESULT_STATUS_PERMISSION_DENIED,
         YUZU_RESULT_COMPLETENESS_PARTIAL},
        {"unsupported", YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_UNKNOWN},
    }};
    static_assert(kPairing.size() == static_cast<std::size_t>(StatusState::unsupported) + 1);
    const Pairing& p = kPairing[static_cast<std::size_t>(status)];
    ctx.write_output("status|list|" + std::string{p.token} + '|' +
                     (reason.empty() ? std::string{"-"} : yuzu::util::safe_output_field(reason)));
    for (const auto& r : data_rows)
        ctx.write_output(r);
    ctx.set_result_status(p.status, p.completeness,
                          status == StatusState::supported ? std::string{} : std::string{reason});
}

/// What a leg decided: the status, its reason token(s), and the data rows.
struct Listing {
    StatusState status = StatusState::supported;
    std::string reason;
    std::vector<std::string> rows;
};

/// A leg that reads nothing reports `{StatusState::unsupported, <token>, {}}`: ONE
/// `unsupported` status row and UNAVAILABLE/UNKNOWN carrying the same token. Callers: the
/// Windows placeholder and execute_list's catch arm (`<os>:leg:exception`).
inline void report_list(yuzu::CommandContext& ctx, const Listing& p) {
    report_list(ctx, p.rows, p.status, p.reason);
}

using LegFn = int (*)(yuzu::CommandContext&);

/// The WHOLE body of the plugin's execute(): dispatch and the single ABI containment. One
/// status row per dispatch, except: an unknown action writes one non-status line and returns 1;
/// a leg that throws after report_list gets the catch arm's `unsupported` row appended (the LAST
/// status row wins); if that recovery throws too, return 1 rather than unwind across the ABI.
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

inline std::string errno_token(int err) {
    switch (err) {
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

/// `<os>:remote_access_audit:<src>:<cause>`
inline std::string src_token(std::string_view os, std::string_view src, std::string_view cause) {
    std::string t{os};
    t += ":remote_access_audit:";
    t += src;
    t += ':';
    t += cause;
    return t;
}

/// Absent is a state, never a failure; a refusal is its own state; everything else that
/// kept the file from being read, and (config side) a NUL byte in what was read, is a failure.
/// `nul_is_failure` is false for key files: sshd reads those line by line and a NUL only cuts
/// its own line short, so the key parser handles it per line (KeysParse::nul_truncated).
inline SrcOutcome classify_read(const FileReadLike& r, std::string_view os, std::string_view src,
                                bool nul_is_failure = true) {
    switch (r.error) {
    case ReadErr::none:
        if (nul_is_failure && r.data.find('\0') != std::string::npos)
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
        if (r.err == EACCES || r.err == EPERM)
            return {SourceState::refused, src_token(os, src, "permission_denied")};
        return {SourceState::failed, src_token(os, src, errno_token(r.err))};
    }
    return {SourceState::failed, src_token(os, src, "unknown")};
}

// ---------------------------------------------------------------------------
// Limits (the README states each; tests pin each)
// ---------------------------------------------------------------------------

inline constexpr std::size_t kConfigFileCap = 256 * 1024; ///< per sshd_config / Include file
inline constexpr std::size_t kKeyFileCap = 1024 * 1024;   ///< per authorized_keys file
inline constexpr std::size_t kMaxHomes = 512;
inline constexpr std::size_t kMaxKeyFileAttempts = 1024; ///< key-file reads attempted, dispatch-wide
inline constexpr std::size_t kMaxDirEntries = 4096;      ///< entries examined per listed directory
inline constexpr std::size_t kSourceRows = 3;            ///< sshd_config, homes, service

/// Collects tokens and the budgeted rows of one listing. ONE RowByteBudget covers EVERY
/// emitted row; the status row is composed by report_list outside it. `denied` keeps refusal
/// tokens in order; every other token goes through the shared ConstraintAccumulator.
struct Tally {
    yuzu::shared::RowByteBudget budget{kMaxRows, kMaxBytes};
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<std::string> denied;
    std::size_t read_sources = 0;
    std::size_t file_attempts = 0;
    bool truncated = false;
    bool field_oversized = false;

    Tally() {
        // The three `source` rows are composed last but must always fit: reserve them now.
        budget.add(kSourceRows * (96 + kRowOverhead), kSourceRows);
    }

    /// Records a source outcome's token. Does NOT count a read source: the three sources do
    /// that themselves, so the per-file notes of the keys half never inflate it.
    void note(const SrcOutcome& o) {
        if (o.token.empty())
            return;
        if (o.state == SourceState::refused) {
            if (std::ranges::find(denied, o.token) == denied.end())
                denied.push_back(o.token);
        } else {
            acc.add_failure(o.token);
        }
    }

    /// Charges the row's size BEFORE it is materialised. false => refused (row_cap).
    bool emit(std::vector<std::string>& rows, std::string row) {
        if (!budget.charge(row.size() + kRowOverhead)) {
            truncated = true;
            return false;
        }
        rows.push_back(std::move(row));
        return true;
    }

    /// Final status: permission_denied only when >=1 source was refused and none was read;
    /// any token -> constrained; else supported.
    Listing finish(std::vector<std::string> rows) {
        Listing l;
        l.rows = std::move(rows);
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

// ---------------------------------------------------------------------------
// The injected boundary
// ---------------------------------------------------------------------------

struct HomeEntry {
    std::string name; ///< the home directory's basename: the row's `account`
    std::string path; ///< the whole home path (never emitted)
};

using RunFn = std::function<yuzu::agent::SubprocessResult(const std::vector<std::string>& args,
                                                          const yuzu::agent::SubprocessOptions&)>;

/// Every I/O the decision logic needs. One PosixFs per execute(): the bound handles
/// (the last listed include directory, the last opened home) make it single-threaded.
struct PosixFs {
    /// "linux" | "macos": the failure-token prefix; "macos" also selects the Data-volume alias
    /// expansion.
    std::string os;
    bool launchd = false; ///< service state from launchctl (macOS) rather than systemctl
    std::string config_path;
    std::vector<std::string> home_roots;

    // --- config + service half ---
    /// Bounded read of one regular file by path (sshd_config, a single Include); a config-side link is followed.
    ReadFn read_config;
    /// Lists the entries of `dir` matching the fnmatch `leaf` (hidden names only if the
    /// pattern starts with '.'), sorted by byte order and cut to kMaxIncludeFiles with
    /// `too_many` set. Returns 0 or the errno of a failed open/readdir.
    std::function<int(const std::string& dir, const std::string& leaf, std::vector<std::string>& names,
                      bool& too_many)>
        list_include_dir;
    /// Reads one listed entry, confined to the directory the last list_include_dir opened.
    std::function<FileReadLike(const std::string& name)> read_include_at;
    /// Runs the OS tool (`systemctl` / `launchctl`) with `args` (the tool path is prepended by
    /// the OS shell, which also answers spawn_error when it cannot be resolved).
    RunFn run;

    // --- keys half ---
    /// Mount points of network filesystems; nullopt = the mount table could not be read.
    std::function<std::optional<std::vector<std::string>>()> network_mount_prefixes;
    /// Optional. Resolves a configured path that is itself a symlink (a home PARENT such as
    /// /home -> var/home, the sshd_config path, an Include file or directory) by ONE readlink
    /// hop to the absolute, normalised path it names; anything else answers `root` unchanged.
    /// Chains, and links among a listed Include directory's entries, are NOT resolved
    /// (README caveat 4). Unset = every path is taken as written.
    std::function<std::string(const std::string& root)> resolve_root;
    /// Lists the account homes under `roots` (already resolved): errno of the first failed
    /// root, ENOENT when every root is absent.
    std::function<int(const std::vector<std::string>& roots, std::vector<HomeEntry>& homes, bool& too_many)>
        list_homes;
    /// Optional account-eligibility predicate, asked AFTER the network-mount check and BEFORE the
    /// home is opened. false only when the entry is positively not an account home (macOS: owned
    /// by a uid under 500); any doubt answers true so open_home surfaces the errno. Unset = every
    /// listed home is an account.
    std::function<bool(const HomeEntry& home)> is_account_home;
    /// Opens `home` no-follow and keeps it for read_key_file. 0 or errno.
    std::function<int(const HomeEntry& home)> open_home;
    /// Reads a file by single path components under the opened home, hop by hop.
    std::function<FileReadLike(const std::vector<std::string>& components)> read_key_file;
    /// Reads an absolute path outside any home, opened from "/" hop by hop; no component is followed.
    ReadFn read_key_file_abs;
};

// ---------------------------------------------------------------------------
// Config half: sshd_config + Include
// ---------------------------------------------------------------------------

struct ConfigOutcome {
    SourceState state = SourceState::absent;
    std::size_t files_read = 0;
};

/// macOS firmlinked volume: a mount listed as `/System/Volumes/Data/<path>` is the same object
/// as `/<path>`, and a firmlink is not a symlink, so neither a prefix compare nor a no-follow
/// open tells the spellings apart.
inline constexpr std::string_view kDataVolume = "/System/Volumes/Data";

/// Adds the other spelling of every mount prefix (stripped / Data-volume form; not "/") so a
/// home or key path matches under either. Pure: no stat, no realpath.
inline void add_data_volume_aliases(std::vector<std::string>& prefixes) {
    std::vector<std::string> aliases;
    for (const std::string_view p : prefixes) {
        if (p.size() <= kDataVolume.size() && p.starts_with(kDataVolume))
            continue; // the Data volume's own root: no alias
        if (p.starts_with(kDataVolume) && p[kDataVolume.size()] == '/')
            aliases.emplace_back(p.substr(kDataVolume.size()));
        else if (p.size() > 1 && p.front() == '/')
            aliases.push_back(std::string{kDataVolume} + std::string{p});
    }
    prefixes.insert(prefixes.end(), aliases.begin(), aliases.end());
}

namespace detail {

/// True when `path` is on or under a listed mount point (segment-boundary match; "/" covers all).
inline bool under_prefix(std::string_view path, const std::vector<std::string>& prefixes) {
    for (const auto& m : prefixes) {
        if (m == "/")
            return true;
        if (path.size() >= m.size() && path.compare(0, m.size(), m) == 0 &&
            (path.size() == m.size() || path[m.size()] == '/'))
            return true;
    }
    return false;
}

/// `path` with empty and `.` components dropped and `..` folded (never above "/"): the one
/// spelling the prefix compare sees, so `//`, `/./` and `/x/../` cannot slip past a byte compare.
/// Lexical only, no filesystem call (a link before a `..` is the disclosed residual).
inline std::string lexical_normal(std::string_view path) {
    std::vector<std::string_view> parts;
    for (std::size_t i = 0; i <= path.size();) {
        const auto slash = path.find('/', i);
        const auto part = path.substr(i, slash == std::string_view::npos ? std::string_view::npos : slash - i);
        if (part == "..") {
            if (!parts.empty())
                parts.pop_back();
        } else if (!part.empty() && part != ".") {
            parts.push_back(part);
        }
        if (slash == std::string_view::npos)
            break;
        i = slash + 1;
    }
    std::string out;
    for (const auto part : parts) {
        out += '/';
        out += part;
    }
    return out.empty() ? "/" : out;
}

/// True when a CONFIGURED path (the config file, an Include file or directory) is on a network
/// mount, judged without touching the mount: the lexically normalised path, then the single
/// readlink hop `resolve_root` answers when the path is itself a link. The path is lstat'ed and,
/// when a link, readlinked; its target is never opened or realpath'ed.
inline bool configured_path_on_network(const PosixFs& fs, const std::vector<std::string>& prefixes,
                                       const std::string& path) {
    const std::string norm = lexical_normal(path);
    return under_prefix(norm, prefixes) ||
           (fs.resolve_root && under_prefix(fs.resolve_root(norm), prefixes));
}

/// True when the entry `name` of a directory is on a mount, judged by name under the lexically
/// normalised configured spelling of the directory and, when it differs, its one-hop resolved
/// spelling. Each joined path is normalised, so a directory resolving to "/" cannot yield "//name".
inline bool entry_on_network(const std::vector<std::string>& prefixes, const std::string& dir_norm,
                             const std::string& dir_resolved, std::string_view name) {
    return under_prefix(lexical_normal(dir_norm + "/" + std::string{name}), prefixes) ||
           (dir_resolved != dir_norm &&
            under_prefix(lexical_normal(dir_resolved + "/" + std::string{name}), prefixes));
}

struct IncludeCtx {
    const PosixFs& fs;
    Tally& t;
    SshdConfigState& st;
    const std::vector<std::string>& prefixes; ///< the run-start network mount snapshot
    std::size_t files_read = 0;
    std::size_t directives = 0; ///< Include patterns (arguments) seen, followed or not
};

inline void walk_include(IncludeCtx& c, const IncludeDirective& d, std::size_t depth);

inline void parse_with_includes(IncludeCtx& c, std::string_view text, std::string_view origin,
                                std::size_t depth) {
    parse_sshd_config(text, origin, c.st,
                      [&](const IncludeDirective& d) { walk_include(c, d, depth + 1); });
}

/// One Include argument, processed AT the directive's position by the sink that called us.
inline void walk_include(IncludeCtx& c, const IncludeDirective& d, std::size_t depth) {
    const auto& os = c.fs.os;
    // Every pattern counts, not only the ones that read a file: a glob that matches nothing
    // lists its directory again each time, and only a successful read raises files_read.
    if (++c.directives > kMaxIncludeFiles) {
        c.t.acc.add_failure(src_token(os, "include", "too_many"));
        return;
    }
    if (d.in_match) {
        c.t.acc.add_failure(src_token(os, "include", "in_match"));
        return;
    }
    if (depth > kMaxIncludeDepth) {
        c.t.acc.add_failure(src_token(os, "include", "depth_cap"));
        return;
    }
    const auto spec = expand_include_pattern(d.pattern);
    if (spec.kind == IncludeSpec::Kind::unsupported) {
        c.t.acc.add_failure(src_token(os, "include", "pattern_unsupported"));
        return;
    }
    if (c.files_read >= kMaxIncludeFiles) {
        c.t.acc.add_failure(src_token(os, "include", "too_many"));
        return;
    }
    // The readers carry no deadline, so an Include file (or a listed directory) on a network
    // mount is never opened. A glob's directory is checked as configured, and each listed entry by
    // name under both spellings of its directory; a single file is checked by name under both
    // spellings of its directory FIRST (the lstat in configured_path_on_network traverses the
    // directory and would reach a dead per-file mount), then as itself. An entry that is itself a
    // link into a mount, or a link chain, is not resolved (README caveat 4).
    const std::string dir_norm = lexical_normal(spec.dir);
    // A directory already on a mount is not lstat'ed again: the entry compare fires lexically.
    const bool lstat_dir = c.fs.resolve_root && !under_prefix(dir_norm, c.prefixes);
    const std::string dir_resolved = lstat_dir ? c.fs.resolve_root(dir_norm) : dir_norm;
    const bool single = spec.kind == IncludeSpec::Kind::single;
    if (single ? (entry_on_network(c.prefixes, dir_norm, dir_resolved, spec.leaf) ||
                  configured_path_on_network(c.fs, c.prefixes, spec.path))
               : (under_prefix(dir_norm, c.prefixes) || under_prefix(dir_resolved, c.prefixes))) {
        c.t.acc.add_failure(src_token(os, "include", "network_mount_skipped"));
        return;
    }

    // Read every matching file BEFORE parsing any: an included file may itself list another
    // directory, which would re-point the listing's directory handle under the loop.
    struct Loaded {
        std::string origin;
        std::string text;
    };
    std::vector<Loaded> loaded;
    const auto take = [&](const FileReadLike& r, std::string origin, bool listed) {
        const SrcOutcome o = classify_read(r, os, "include");
        if (o.state == SourceState::read) {
            ++c.files_read;
            loaded.push_back({std::move(origin), r.data});
        } else if (o.state == SourceState::absent && listed) {
            // A name the directory listed that then reads absent is a dangling link: sshd
            // exits when it cannot open an included file, so this is never silent.
            c.t.acc.add_failure(src_token(os, "include", "enoent"));
        } else {
            c.t.note(o); // absent single path -> no token (a glob with no match is silent in sshd too)
        }
    };
    if (spec.kind == IncludeSpec::Kind::single) {
        take(c.fs.read_config(spec.path), include_origin(spec.path), false);
    } else {
        std::vector<std::string> names;
        bool too_many = false;
        const int err = c.fs.list_include_dir(spec.dir, spec.leaf, names, too_many);
        if (err != 0) {
            c.t.note(classify_read(FileReadLike{{}, ReadErr::io, err}, os, "include"));
        } else {
            if (too_many)
                c.t.acc.add_failure(src_token(os, "include", "too_many"));
            for (const auto& n : names) {
                if (c.files_read >= kMaxIncludeFiles) {
                    c.t.acc.add_failure(src_token(os, "include", "too_many"));
                    break;
                }
                // Lexical by name, under both spellings of the directory; no per-entry readlink.
                if (entry_on_network(c.prefixes, dir_norm, dir_resolved, n)) {
                    c.t.acc.add_failure(src_token(os, "include", "network_mount_skipped"));
                    continue;
                }
                take(c.fs.read_include_at(n), include_origin(n), true);
            }
        }
    }
    for (const auto& l : loaded)
        parse_with_includes(c, l.text, l.origin, depth);
}

} // namespace detail

/// Reads sshd_config and follows every Include in directive order. Fills `st`; adds the
/// sshd_config/include tokens; never emits a row. `prefixes` is the run-start network mount
/// snapshot: neither the config file nor an Include path on a mount is opened (`failed` +
/// `network_mount_skipped`).
inline ConfigOutcome audit_config(const PosixFs& fs, Tally& t, SshdConfigState& st,
                                  const std::vector<std::string>& prefixes) {
    ConfigOutcome out;
    if (detail::configured_path_on_network(fs, prefixes, fs.config_path)) {
        out.state = SourceState::failed;
        t.note(SrcOutcome{SourceState::failed, src_token(fs.os, "sshd_config", "network_mount_skipped")});
        return out;
    }
    const FileReadLike r = fs.read_config(fs.config_path);
    const SrcOutcome o = classify_read(r, fs.os, "sshd_config");
    out.state = o.state;
    t.note(o);
    if (o.state != SourceState::read)
        return out;
    ++t.read_sources;
    detail::IncludeCtx c{fs, t, st, prefixes, 1};
    detail::parse_with_includes(c, r.data, "sshd_config", 0);
    out.files_read = c.files_read;
    if (st.invalid_quotes)
        t.acc.add_failure(src_token(fs.os, "sshd_config", "invalid_quotes"));
    // A credential source this plugin does not read (CA trust, a key or principals command, a
    // principals file, hostbased auth, AuthenticationMethods): the key listing below is not the
    // whole answer to "who can log in", so the listing cannot be `supported`.
    if (st.other_credential_sources)
        t.acc.add_failure(src_token(fs.os, "sshd_config", "other_credential_sources"));
    return out;
}

// ---------------------------------------------------------------------------
// Config half: sshd service state
// ---------------------------------------------------------------------------

struct ServiceOutcome {
    SourceState state = SourceState::absent;
    std::size_t units = 0; ///< units queried
    std::vector<std::string> rows;
};

namespace detail {

inline yuzu::agent::SubprocessOptions service_options(std::size_t max_lines, std::size_t cap_bytes,
                                                      bool merge_stderr) {
    yuzu::agent::SubprocessOptions o;
    o.deadline = std::chrono::milliseconds{5000};
    o.max_lines = max_lines;
    o.output_cap_bytes = cap_bytes;
    o.merge_stderr = merge_stderr;
    return o;
}

/// A runner failure (or truncation) -> the token to record; nullopt = the output is usable.
/// `unavailable` is set for a tool that could not be started at all, whose token names the
/// caller's own tool (`unavailable_cause`: systemctl_unavailable / launchctl_unavailable).
inline std::optional<std::string> service_failure(const yuzu::agent::SubprocessResult& r, std::string_view os,
                                                  std::string_view unavailable_cause, bool& unavailable) {
    unavailable = false;
    if (const auto f = yuzu::agent::classify_runner_failure(r)) {
        if (f->status == YUZU_RESULT_STATUS_UNAVAILABLE) {
            unavailable = true;
            return src_token(os, "service", unavailable_cause);
        }
        return std::string{f->provenance};
    }
    if (r.output_truncated)
        return src_token(os, "service", "output_truncated");
    return std::nullopt;
}

} // namespace detail

/// `systemctl is-enabled` once per unit (compile-time literals). A tool that cannot be
/// started is a FAILED service source and NO service row -- never `disabled`. stderr is merged
/// into the captured output: systemd 249/252 name a missing unit only there
/// (parse_systemctl_is_enabled).
inline ServiceOutcome audit_service_linux(const PosixFs& fs, Tally& t) {
    static constexpr std::array<std::string_view, 4> kUnits = {"ssh.service", "sshd.service",
                                                               "ssh.socket", "sshd.socket"};
    ServiceOutcome out;
    bool any_answered = false;
    for (const auto unit : kUnits) {
        ++out.units;
        const auto r = fs.run({"is-enabled", std::string{unit}}, detail::service_options(4, 4096, /*merge_stderr=*/true));
        bool unavailable = false;
        if (const auto bad = detail::service_failure(r, fs.os, "systemctl_unavailable", unavailable)) {
            t.acc.add_failure(*bad);
            if (unavailable) {
                out.rows.clear();
                out.state = SourceState::failed;
                return out;
            }
            t.emit(out.rows, service_row(unit, "unknown", "systemctl_is_enabled"));
            continue;
        }
        const ServiceFact f = parse_systemctl_is_enabled(r.output, r.exit_code, unit);
        if (!f.cause.empty())
            t.acc.add_failure(src_token(fs.os, "service", f.cause));
        else
            any_answered = true;
        t.emit(out.rows, service_row(unit, f.state, "systemctl_is_enabled"));
    }
    out.state = any_answered ? SourceState::read : SourceState::failed;
    if (any_answered)
        ++t.read_sources;
    return out;
}

/// `launchctl print-disabled system`, one spawn, one label. No entry for the label is
/// `unknown`, never `disabled`: the override database only lists labels that were toggled.
inline ServiceOutcome audit_service_macos(const PosixFs& fs, Tally& t) {
    ServiceOutcome out;
    out.units = 1;
    const auto r = fs.run({"print-disabled", "system"},
                          detail::service_options(4096, 256 * 1024, /*merge_stderr=*/false));
    bool unavailable = false;
    if (const auto bad = detail::service_failure(r, fs.os, "launchctl_unavailable", unavailable)) {
        t.acc.add_failure(*bad);
        out.state = SourceState::failed;
        return out;
    }
    if (r.exit_code != 0) {
        t.acc.add_failure(src_token(fs.os, "service", "exit_nonzero"));
        out.state = SourceState::failed;
        return out;
    }
    if (!looks_like_print_disabled(r.output)) {
        t.acc.add_failure(src_token(fs.os, "service", "unrecognised_output"));
        out.state = SourceState::failed;
        return out;
    }
    constexpr std::string_view kLabel = "com.openssh.sshd";
    std::string_view state = "unknown";
    switch (parse_print_disabled_label(r.output, kLabel)) {
    case LaunchState::enabled:
        state = "enabled";
        break;
    case LaunchState::disabled:
        state = "disabled";
        break;
    case LaunchState::absent:
        break;
    }
    t.emit(out.rows, service_row(kLabel, state, "launchctl_print_disabled"));
    out.state = SourceState::read;
    ++t.read_sources;
    return out;
}

// ---------------------------------------------------------------------------
// Keys half: per-account authorized_keys
// ---------------------------------------------------------------------------

struct KeysOutcome {
    SourceState homes_state = SourceState::absent;
    std::size_t accounts = 0;
    /// Listed home-root entries the eligibility probe refused; nullopt when no probe is wired
    /// (Linux) or the roots were not listed. Counts the homes examined before any early stop.
    std::optional<std::size_t> skipped_homes;
    std::vector<std::string> rows;
};

namespace detail {

inline std::string join_path(std::string_view home, const std::vector<std::string>& components) {
    std::string p{home};
    for (const auto& c : components) {
        p += '/';
        p += c;
    }
    return p;
}

} // namespace detail

/// Walks every account home. Entries are RESOLVED first (P7) so a readable absolute
/// AuthorizedKeysFile entry never depends on the home being openable; the home is opened
/// only when at least one entry is home-relative. A network mount named by `prefixes` (the
/// run-start snapshot) is never touched (P8).
inline KeysOutcome audit_keys(const PosixFs& fs, const SshdConfigState& cfg, Tally& t,
                              const std::vector<std::string>& prefixes) {
    KeysOutcome out;
    const auto& os = fs.os;
    const auto token = [&](std::string_view cause) { return src_token(os, "keys", cause); };

    if (cfg.akf_in_match)
        t.acc.add_failure(token("match_scoped_authorizedkeysfile"));
    if (cfg.akf_count > kMaxAuthorizedKeysFileTokens)
        t.acc.add_failure(token("path_token_cap"));

    std::vector<std::string> entries;
    if (!cfg.akf_set)
        entries = {".ssh/authorized_keys", ".ssh/authorized_keys2"};
    else if (!(cfg.akf.size() == 1 && detail::lower(cfg.akf[0]) == "none"))
        entries = cfg.akf;

    // A home root on a network mount is never listed. The configured path is checked first (no
    // syscall); a root that is itself a link is then resolved by readlink alone and its target
    // checked too, so a parent linked into a mount is skipped before anything is opened.
    std::vector<std::string> roots;
    for (const auto& r : fs.home_roots) {
        std::string resolved = r;
        bool network = detail::under_prefix(r, prefixes);
        if (!network && fs.resolve_root) {
            resolved = fs.resolve_root(r);
            network = detail::under_prefix(resolved, prefixes);
        }
        if (network)
            t.acc.add_failure(token("network_mount_skipped"));
        else
            roots.push_back(std::move(resolved));
    }
    std::vector<HomeEntry> homes;
    bool too_many = false;
    const int lerr = roots.empty() ? ENOENT : fs.list_homes(roots, homes, too_many);
    if (lerr == 0) {
        out.homes_state = SourceState::read;
        ++t.read_sources;
    } else {
        const SrcOutcome lo = classify_read(FileReadLike{{}, ReadErr::io, lerr}, os, "homes");
        out.homes_state = lo.state;
        t.note(lo);
    }
    if (too_many)
        t.acc.add_failure(src_token(os, "homes", "too_many"));
    if (lerr != 0)
        return out;

    if (fs.is_account_home)
        out.skipped_homes = 0;
    bool attempts_exhausted = false;
    const auto take_attempt = [&]() {
        if (t.file_attempts >= kMaxKeyFileAttempts) {
            if (!attempts_exhausted)
                t.acc.add_failure(token("file_cap"));
            attempts_exhausted = true;
            return false;
        }
        ++t.file_attempts;
        return true;
    };

    for (const auto& home : homes) {
        if (t.truncated || attempts_exhausted)
            break;
        // Order: network prefix -> eligibility -> lazy open_home. A home on a network mount is
        // never stat'ed or opened (it is reported failed below); on any other home the
        // eligibility probe runs before anything opens it, and a home that is positively not an
        // account has no row and is counted in the homes row's skipped field.
        const bool on_network = detail::under_prefix(home.path, prefixes);
        if (!on_network && fs.is_account_home && !fs.is_account_home(home)) {
            ++*out.skipped_homes;
            continue;
        }
        ++out.accounts;

        std::vector<KeyFileSpec> specs;
        for (const auto& e : entries) {
            if (auto s = expand_authorized_keys_file(e, home.path))
                specs.push_back(std::move(*s));
            else
                t.acc.add_failure(token("path_token_unsupported"));
        }

        // Records one file's outcome: its file row and, when read, its key rows.
        const auto record = [&](const KeyFileSpec& s, const FileReadLike& r) {
            const SrcOutcome o = classify_read(r, os, "keys", /*nul_is_failure=*/false);
            t.note(o);
            std::optional<std::size_t> nk, nm, no;
            std::vector<std::string> krows;
            if (o.state == SourceState::read) {
                // The file row is charged BEFORE its key rows (worst-case size), so a file that
                // saturates the budget keeps its file row and its first N keys.
                bool ignored = false;
                const std::string worst_row = file_row(home.name, s.kind, o.state, kKeyFileCap,
                                                       kKeyFileCap, kKeyFileCap, ignored);
                const std::size_t file_row_cost = worst_row.size() + kRowOverhead;
                if (!t.budget.charge(file_row_cost)) {
                    t.truncated = true;
                    return;
                }
                KeysParse kp;
                parse_authorized_keys(r.data, home.name, s.kind, t.budget, kp);
                if (kp.truncated)
                    t.truncated = true;
                if (kp.malformed > 0)
                    t.acc.add_failure(token("malformed"));
                if (kp.oversized > 0)
                    t.acc.add_failure(token("oversized_line"));
                if (kp.unknown_type)
                    t.acc.add_failure(token("unknown_key_type"));
                if (kp.nul_truncated)
                    t.acc.add_failure(token("invalid_bytes"));
                t.field_oversized = t.field_oversized || kp.field_oversized;
                nk = kp.keys;
                nm = kp.malformed;
                no = kp.oversized;
                krows = std::move(kp.rows);
            }
            if (o.state == SourceState::read) {
                out.rows.push_back(file_row(home.name, s.kind, o.state, nk, nm, no,
                                            t.field_oversized)); // charged above
                for (auto& k : krows)
                    out.rows.push_back(std::move(k)); // charged inside the parse
            } else {
                t.emit(out.rows,
                       file_row(home.name, s.kind, o.state, nk, nm, no, t.field_oversized));
            }
        };
        const auto record_failed = [&](const KeyFileSpec& s, SourceState st, std::string tok) {
            if (st == SourceState::refused)
                t.note(SrcOutcome{SourceState::refused, std::move(tok)});
            else
                t.acc.add_failure(tok);
            t.emit(out.rows, file_row(home.name, s.kind, st, std::nullopt, std::nullopt,
                                      std::nullopt, t.field_oversized));
        };

        // A home on a network mount is not touched at all.
        if (on_network) {
            for (const auto& s : specs)
                record_failed(s, SourceState::failed, token("network_mount_skipped"));
            continue;
        }

        // Entries in configuration order. An absolute entry outside the home never depends on
        // the home opening; the home is opened lazily, at the first home-relative entry, so it
        // is not opened at all when every entry is absolute.
        bool open_tried = false;
        int oerr = 0;
        for (const auto& s : specs) {
            if (t.truncated || attempts_exhausted)
                break;
            if (s.where == KeyFileSpec::Where::absolute) {
                if (!take_attempt())
                    break;
                if (detail::under_prefix(s.path, prefixes))
                    record_failed(s, SourceState::failed, token("network_mount_skipped"));
                else
                    record(s, fs.read_key_file_abs(s.path));
                continue;
            }
            if (!open_tried) {
                open_tried = true;
                oerr = fs.open_home(home);
            }
            if (oerr == ENOENT)
                continue; // the home vanished between the listing and the open: a snapshot of a changing directory
            if (oerr != 0) {
                const SrcOutcome lo = classify_read(FileReadLike{{}, ReadErr::io, oerr}, os, "homes");
                record_failed(s, lo.state, lo.token);
                continue;
            }
            if (!take_attempt())
                break;
            const std::string full = detail::join_path(home.path, s.components);
            if (detail::under_prefix(full, prefixes))
                record_failed(s, SourceState::failed, token("network_mount_skipped"));
            else
                record(s, fs.read_key_file(s.components));
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// The whole POSIX listing
// ---------------------------------------------------------------------------

inline Listing list_posix(const PosixFs& fs) {
    Tally t;
    SshdConfigState cfg;

    // ONE mount snapshot for the whole listing, taken before the first path is touched: the
    // config half and the keys half both decide against it (the table itself is a bounded
    // no-follow read of /proc/self/mountinfo or the kernel's getmntinfo cache, never a mount).
    std::vector<std::string> prefixes;
    if (auto p = fs.network_mount_prefixes()) {
        prefixes = std::move(*p);
        // a mount the system creates is listed under /System/Volumes/Data (macOS firmlink)
        if (fs.os == "macos")
            add_data_volume_aliases(prefixes);
    } else
        t.acc.add_failure(src_token(fs.os, "keys", "mounts_unreadable"));

    const ConfigOutcome co = audit_config(fs, t, cfg, prefixes);
    std::vector<std::string> config_rows_out;
    {
        bool oversized = false;
        for (auto& r : config_rows(cfg, co.state == SourceState::read, oversized)) {
            if (!t.emit(config_rows_out, std::move(r)))
                break;
        }
        t.field_oversized = t.field_oversized || oversized;
    }
    const ServiceOutcome so = fs.launchd ? audit_service_macos(fs, t) : audit_service_linux(fs, t);
    const KeysOutcome ko = audit_keys(fs, cfg, t, prefixes);

    if (t.truncated)
        t.acc.add_failure(src_token(fs.os, "keys", "row_cap"));
    if (t.field_oversized)
        t.acc.add_failure(src_token(fs.os, "keys", "field_oversized"));

    std::vector<std::string> rows;
    rows.push_back(source_row("sshd_config", co.state,
                              co.state == SourceState::read ? std::optional<std::size_t>{co.files_read} : std::nullopt));
    rows.push_back(homes_source_row(ko.homes_state,
                                    ko.homes_state == SourceState::read ? std::optional<std::size_t>{ko.accounts} : std::nullopt,
                                    ko.homes_state == SourceState::read ? ko.skipped_homes : std::nullopt));
    rows.push_back(source_row("service", so.state,
                              so.state == SourceState::read ? std::optional<std::size_t>{so.units} : std::nullopt));
    for (auto& r : config_rows_out)
        rows.push_back(std::move(r));
    for (const auto& r : so.rows)
        rows.push_back(r);
    for (const auto& r : ko.rows)
        rows.push_back(r);
    return t.finish(std::move(rows));
}

} // namespace yuzu::remote_access_audit
