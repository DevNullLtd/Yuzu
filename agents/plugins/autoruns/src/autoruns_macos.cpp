/**
 * autoruns_macos.cpp — macOS leg (P14) of the autoruns plugin's `collect_*`
 * trio (autoruns_legs.hpp).
 *
 * Sources covered (all eight macOS SourceIds, autoruns_catalog.hpp):
 *   - /Library/{LaunchDaemons,LaunchAgents}                (system)
 *   - /System/Library/{LaunchDaemons,LaunchAgents}         (system, apple_system by path)
 *   - /Users/(each real home)/Library/LaunchAgents         (user, per real home directory)
 *   - Login Items                                          (mac_login_items — always CONSTRAINED,
 *                                                            no public read API; see below)
 *   - /etc/periodic/{daily,weekly,monthly} scripts         (mac_periodic)
 *   - /etc/emond.d/rules/ plists                           (mac_emond)
 *
 * File truth only, rung 1: no launchctl, no osascript, no sfltool — zero
 * process spawns anywhere in this leg. This is a DELIBERATE divergence from
 * a services-style plugin that reads `launchctl print-disabled` overrides:
 * a plist's own `Disabled` key is read, but launchctl's separate override
 * database (which can re-enable a Disabled=true job, or vice versa) is not
 * consulted — this leg reports the file's own claim, not launchd's live
 * runtime state.
 *
 * Login Items has no file this leg can read at all: the list lives in a
 * private per-user BTM (Background Task Management) database with no
 * public API (autoruns_catalog.hpp's own documented CONSTRAINED rationale —
 * the only route is osascript driving System Events, a rung-3 governed-shell
 * acquisition this leg does not perform). So `mac_login_items` always emits
 * the same constrained status line and zero rows, never a real read attempt.
 *
 * The CFPropertyListCreateWithData plist read itself is header-only
 * (autoruns_macos.hpp's `plist_to_launchd_fields`) so the test binary can
 * exercise it directly against real captured fixtures; this TU does the
 * directory walk and hands each file's bytes to that header function (for
 * launchd plists) or to this TU's own local emond-rule extraction (below —
 * emond's row shape, EmondRuleFields, is not launchd's, so it is not routed
 * through plist_to_launchd_fields, though it uses the same
 * CFPropertyListCreateWithData primitive).
 */
#ifdef __APPLE__

#include "autoruns_catalog.hpp"
#include "autoruns_macos.hpp"
#include "autoruns_parsers.hpp"

#include <constraint_accumulator.hpp>
#include <posix_dir_walk.hpp>
#include <yuzu/agent/scoped_cfref.hpp>
#include <yuzu/plugin.hpp>

#include <CoreFoundation/CoreFoundation.h>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::autoruns {

namespace {

constexpr std::size_t kMaxEntriesPerDir = 4096;
constexpr std::size_t kMaxPlistBytes = 1024 * 1024; // 1 MiB, same cap as P13's read_file_bounded

/// Move-only RAII owner for a POSIX DIR*; closes exactly once, including on
/// an early return mid-walk.
class DirHandle {
public:
    explicit DirHandle(DIR* d) noexcept : dir_(d) {}
    ~DirHandle() {
        if (dir_ != nullptr) closedir(dir_);
    }
    DirHandle(const DirHandle&) = delete;
    DirHandle& operator=(const DirHandle&) = delete;
    [[nodiscard]] DIR* get() const noexcept { return dir_; }
    [[nodiscard]] bool valid() const noexcept { return dir_ != nullptr; }

private:
    DIR* dir_;
};

/// Move-only RAII owner for a POSIX fd; closes exactly once. Not used for a
/// fd handed to fdopendir() — DirHandle owns that one once fdopendir
/// succeeds (closedir() closes the underlying fd too; double-closing it here
/// as well would be a double-close bug, not a safety net).
class FdHandle {
public:
    explicit FdHandle(int fd) noexcept : fd_(fd) {}
    ~FdHandle() {
        if (fd_ >= 0) close(fd_);
    }
    FdHandle(const FdHandle&) = delete;
    FdHandle& operator=(const FdHandle&) = delete;
    [[nodiscard]] int get() const noexcept { return fd_; }
    [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }

private:
    int fd_;
};

/// Injectable metadata-read seam for `walk_dir_names` and
/// `collect_user_launchagents` (issue #4241's fault-injection tests):
/// defaults to the real syscalls on every production call site (never
/// passed explicitly there); only test code, via the
/// YUZU_AUTORUNS_MACOS_UNIT_TEST_INTERNALS_ONLY TU-inclusion seam, ever
/// supplies its own to simulate an EACCES/EIO mid-walk without needing a
/// real unreadable file on disk.
struct StatFns {
    // No trailing underscore (docs/cpp-conventions.md reserves that for
    // PRIVATE members; these fields are a plain public aggregate, matching
    // posix_dir_walk.hpp's sibling seam ReadDirFn's plain `readdir_fn`
    // naming) -- `_fn` instead, naming what each field IS.
    int (*fstat_fn)(int, struct stat*) = &::fstat;
    int (*fstatat_fn)(int, const char*, struct stat*, int) = &::fstatat;
};

/// Outcome of an O_NOFOLLOW directory open: the handle (invalid on any
/// failure), plus whether that failure is a real constraint (permission
/// denied, a refused symlink, a path component that wasn't a directory —
/// anything but a genuinely-absent path) and, if so, a reason token for the
/// `constrained` status line. `reason` is empty whenever `constrained` is
/// false, whether the open succeeded or the path was simply absent.
struct DirOpenOutcome {
    DirHandle handle;
    bool constrained = false;
    std::string_view reason{};
};

/// Classifies an already-attempted `open`/`openat` result (`fd`, with
/// `errno` still current from that call if `fd < 0`) into a DirOpenOutcome,
/// completing the open via `fdopendir()` on success. A genuinely-absent
/// directory (ENOENT) is reported as a plain invalid handle with
/// `constrained=false` — several of this leg's paths are legitimately
/// absent on a given host (emond is removed on every captured host; a fresh
/// install may have no /Library/LaunchDaemons entries at all), and "absent"
/// is not this leg's error to report. Any OTHER open failure (permission
/// denied, a refused symlink, a non-directory component) is a real
/// constraint the caller must surface, never silently folded into "zero
/// rows" (autoruns' AC4: failure != empty).
DirOpenOutcome dir_open_outcome_from_fd(int fd) {
    if (fd < 0) {
        const int err = errno;
        if (is_benign_absent_errno(err)) return DirOpenOutcome{DirHandle{nullptr}, false, {}};
        return DirOpenOutcome{DirHandle{nullptr}, true, dir_open_constraint_token(err)};
    }
    DIR* d = fdopendir(fd);
    if (d == nullptr) {
        const int err = errno;
        close(fd);
        if (is_benign_absent_errno(err)) return DirOpenOutcome{DirHandle{nullptr}, false, {}};
        return DirOpenOutcome{DirHandle{nullptr}, true, dir_open_constraint_token(err)};
    }
    return DirOpenOutcome{DirHandle{d}, false, {}};
}

/// Opens `path` refusing to follow a symlink at that exact component
/// (O_NOFOLLOW). See dir_open_outcome_from_fd for the absence-vs-constraint
/// contract.
DirOpenOutcome open_dir_no_follow_checked(const std::string& path) {
    return dir_open_outcome_from_fd(open(path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW));
}

/// Same contract as open_dir_no_follow_checked, but resolves exactly one
/// path COMPONENT (`name`) via `openat(parent_fd, ...)` rather than a fresh
/// `open()` on a joined path string. This is the primitive
/// collect_user_launchagents needs to stay confined to a caller-verified
/// home directory: opening "home/Library/LaunchAgents" as one string lets
/// the kernel resolve the intermediate "Library" component through normal
/// (symlink-following) path resolution, even though the leaf itself is
/// O_NOFOLLOW-checked — a user-owned symlink swapped in for "Library" would
/// escape confinement. Chaining this hop-by-hop from an already-opened
/// parent fd (mirroring agents/core/src/confined_fs_posix.cpp's
/// `open_dir_at`) makes every component's own O_NOFOLLOW check independent
/// of how the previous one resolved.
DirOpenOutcome open_dir_no_follow_at_checked(int parent_fd, const char* name) {
    return dir_open_outcome_from_fd(openat(parent_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW));
}

bool ends_with(std::string_view s, std::string_view suffix) noexcept {
    return s.size() >= suffix.size() && s.substr(s.size() - suffix.size()) == suffix;
}

/// `sources=` is a comma-separated SourceId allow-list; empty means every
/// source runs (the common, unfiltered `list` case this plugin's dispatcher
/// test exercises).
bool source_in_filter(std::string_view filter, SourceId id) noexcept {
    if (filter.empty()) return true;
    const std::string_view name = source_id_string(id);
    std::size_t pos = 0;
    while (pos <= filter.size()) {
        const std::size_t comma = filter.find(',', pos);
        const std::string_view tok =
            comma == std::string_view::npos ? filter.substr(pos) : filter.substr(pos, comma - pos);
        if (tok == name) return true;
        if (comma == std::string_view::npos) break;
        pos = comma + 1;
    }
    return false;
}

/// Returns true iff `support` is CONSTRAINED (never UNSUPPORTED -- a normal,
/// expected outcome, not a degradation -- and never plain SUPPORTED), so
/// every call site can accumulate the leg-wide degradation aggregate
/// collect_macos returns to do_list (autoruns_plugin.cpp), which folds it
/// into the plugin's typed CC-07 result status.
bool emit_status(yuzu::CommandContext& ctx, SourceId id, YuzuSupportLevel support,
                 std::optional<std::size_t> rows, std::string_view reason) {
    ctx.write_output(format_source_status(id, support, rows, reason));
    return support == YUZU_SUPPORT_CONSTRAINED;
}

/// Reads `name` inside the directory backing `dir_fd`, refusing a symlink
/// (constrained, reason) for a failed read_file_bounded call -- benign
/// absence (ENOENT: a raced deletion between listing and reading) contra a
/// real per-entry constraint (permission denied, a refused symlink, a
/// non-regular leaf) that must not be silently folded into "this file
/// contributes nothing" (AC4).
struct PlistReadOutcome {
    bool constrained = false;
    std::string_view reason{};
};

/// (O_NOFOLLOW) at the leaf itself, capped at kMaxPlistBytes. Returns false
/// on any open/fstat/read failure or on a rejected symlink — this is a
/// best-effort collector: a file it cannot read contributes nothing rather
/// than aborting the whole directory's walk, but a real failure (as opposed
/// to a benign race) is reported via `outcome` for the caller to surface.
bool read_file_bounded(int dir_fd, const char* name, std::vector<uint8_t>& out,
                       std::int64_t& mtime, PlistReadOutcome& outcome) {
    FdHandle fd(openat(dir_fd, name, O_RDONLY | O_NOFOLLOW));
    if (!fd.valid()) {
        const int err = errno;
        if (!is_benign_absent_errno(err)) outcome = {true, dir_open_constraint_token(err)};
        return false;
    }
    struct stat st{};
    if (fstat(fd.get(), &st) != 0) {
        const int err = errno;
        if (!is_benign_absent_errno(err)) outcome = {true, dir_open_constraint_token(err)};
        return false;
    }
    if (!S_ISREG(st.st_mode)) {
        outcome = {true, "not_regular"};
        return false;
    }
    mtime = static_cast<std::int64_t>(st.st_mtime);
    const std::size_t want = static_cast<std::size_t>(st.st_size) > kMaxPlistBytes
                                 ? kMaxPlistBytes
                                 : static_cast<std::size_t>(st.st_size);
    out.resize(want);
    std::size_t total = 0;
    while (total < want) {
        const ssize_t n = read(fd.get(), out.data() + total, want - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            const int err = errno;
            if (!is_benign_absent_errno(err)) outcome = {true, dir_open_constraint_token(err)};
            return false;
        }
        if (n == 0) break;
        total += static_cast<std::size_t>(n);
    }
    out.resize(total);
    return true;
}

/// Enumerates `*.plist` entries in an already-opened directory (no
/// Outcome of a directory-plist walk: whether the entry cap was hit with
/// real entries left unread, and whether any listed file failed to read
/// for a real reason (not a benign raced-deletion). Deliberately holds no
/// DirHandle -- a plain, trivially-returned value type, same shape as
/// DirConstraint but with the two signals kept separate so a caller can
/// choose which one wins when combining with its own constraint state.
struct DirWalkOutcome {
    bool truncated = false;
    bool enumeration_error = false;
    bool file_constrained = false;
    std::string_view file_constrained_reason{};
};

/// Enumerates `*.plist` entries in an already-opened directory (no
/// recursion), capped at kMaxEntriesPerDir, and hands each one's bytes +
/// mtime to `on_plist`. `truncated` is true when the cap was hit AND at
/// least one more entry remained unread (probed via one extra `readdir()`
/// after the loop) -- a listing that happened to have exactly
/// kMaxEntriesPerDir entries is NOT truncated. `file_constrained` is true
/// when a listed `*.plist` failed to read for a real reason (permission
/// denied, a refused symlink, a non-regular leaf) rather than a benign
/// raced deletion -- a caller must surface either signal as a constraint
/// (AC4), never silently report a partial/lossy listing as complete. An
/// invalid handle (directory absent, or a component along the way was
/// refused) silently contributes zero rows and an empty outcome -- the
/// same "absence is not an error" contract every rung-1 leg here follows.
template <typename OnPlist>
DirWalkOutcome walk_plist_dir_handle(const DirHandle& dir, OnPlist&& on_plist,
                                     std::size_t cap = kMaxEntriesPerDir) {
    DirWalkOutcome outcome;
    if (!dir.valid()) return outcome;
    const int dfd = dirfd(dir.get());
    // yuzu::shared::walk_dir_capped (agents/shared/posix_dir_walk.hpp) --
    // one shared, correct capped-listing primitive used by every directory
    // walk in this file, instead of three separate hand-rolled copies (PR
    // #4154 round 8 found the terminal-error-detection fix landed one round
    // earlier had a gap of the same shape independently reproduced in all
    // three; the fix now lives in exactly one place). Its `cap` counts
    // EVERY real (non-`.`/`..`) entry the walk visits -- including ones the
    // `.plist` filter below will go on to reject -- because the callback
    // below runs once per directory entry and `walk_dir_capped` counts a
    // call to it, not a call that returned a plist. A directory with many
    // unrelated (non-`.plist`) files can still hit the cap before any real
    // `.plist` is found; this is NOT scoped to "only entries this walk
    // cares about", and this function's callers must treat a cap-boundary
    // `truncated` result as "more entries existed", never as "more `.plist`
    // entries existed".
    const auto walk = yuzu::shared::walk_dir_capped(
        dir.get(), cap, [&](const struct dirent* entry) {
            const std::string_view name(entry->d_name);
            if (!ends_with(name, ".plist")) return true;
            std::vector<uint8_t> bytes;
            std::int64_t mtime = 0;
            PlistReadOutcome read_outcome;
            if (!read_file_bounded(dfd, entry->d_name, bytes, mtime, read_outcome)) {
                if (read_outcome.constrained) {
                    outcome.file_constrained = true;
                    outcome.file_constrained_reason = read_outcome.reason;
                }
                return true;
            }
            on_plist(entry->d_name, bytes, mtime);
            return true;
        });
    outcome.truncated = walk.truncated;
    outcome.enumeration_error = walk.enumeration_error;
    return outcome;
}

/// Enumerates `*.plist` entries directly under `dir_path` (no recursion) by
/// opening the whole path in one shot — safe ONLY when `dir_path` is a
/// single trusted component below a root the OS already protects (e.g.
/// `/Library/LaunchDaemons`), never below a path segment an unprivileged
/// user controls (see open_dir_no_follow_at_checked's banner and
/// collect_user_launchagents, which does NOT use this).
/// Whether a directory-level walk hit a real constraint opening its root
/// (vs. a genuine absence) — deliberately holds no DirHandle so it's a
/// plain, trivially-returned value type.
struct DirConstraint {
    bool constrained = false;
    std::string_view reason{};
};

/// Same enumeration as above, plus the directory-open outcome so the caller
/// can distinguish "genuinely absent" from a real constraint (AC4).
template <typename OnPlist>
DirConstraint walk_plist_dir(const std::string& dir_path, OnPlist&& on_plist) {
    DirOpenOutcome open = open_dir_no_follow_checked(dir_path);
    const auto walk_outcome = walk_plist_dir_handle(open.handle, std::forward<OnPlist>(on_plist));
    if (walk_outcome.truncated) return DirConstraint{true, "row_cap"};
    if (walk_outcome.enumeration_error) return DirConstraint{true, "readdir_error"};
    if (walk_outcome.file_constrained) return DirConstraint{true, walk_outcome.file_constrained_reason};
    return DirConstraint{open.constrained, open.reason};
}

/// Enumerates every non-directory entry (regular file or symlink — periodic
/// scripts are sometimes one, e.g. a Homebrew formula symlinking into
/// /etc/periodic/daily) directly under `dir_path`, capped at
/// kMaxEntriesPerDir, handing each name + its own (non-dereferenced) mtime
/// to `on_entry`. No content is read here — periodic scripts carry no
/// structured metadata this plugin decodes, only their existence and mtime.
template <typename OnEntry>
DirConstraint walk_dir_names(const std::string& dir_path, OnEntry&& on_entry,
                             const StatFns& stat_fns = {}) {
    DirOpenOutcome open = open_dir_no_follow_checked(dir_path);
    if (!open.handle.valid()) return DirConstraint{open.constrained, open.reason};
    const int dfd = dirfd(open.handle.get());
    bool stat_constrained = false;
    std::string_view stat_reason{};
    const auto walk = yuzu::shared::walk_dir_capped(
        open.handle.get(), kMaxEntriesPerDir, [&](const struct dirent* entry) {
            struct stat st{};
            if (stat_fns.fstatat_fn(dfd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
                // #4241: a real fstatat() failure (permission denied, a
                // refused symlink, a genuine I/O error) must not be
                // silently read as "this entry contributes nothing" -- only
                // a benign ENOENT race (the entry vanished between readdir
                // and stat) is. First non-benign failure wins, matching
                // this file's other single-reason accumulation sites.
                const int stat_err = errno;
                if (const auto token = stat_constraint_token(stat_err); token && !stat_constrained) {
                    stat_constrained = true;
                    stat_reason = *token;
                }
                return true;
            }
            if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) return true;
            on_entry(entry->d_name, static_cast<std::int64_t>(st.st_mtime));
            return true;
        });
    if (walk.truncated) return DirConstraint{true, "row_cap"};
    if (walk.enumeration_error) return DirConstraint{true, "readdir_error"};
    if (stat_constrained) return DirConstraint{true, stat_reason};
    return DirConstraint{};
}

/// Local CF plist parse for emond rules: identical primitive to
/// autoruns_macos.hpp's plist_to_launchd_fields (CFDataCreate ->
/// CFPropertyListCreateWithData), but returning the raw root object rather
/// than a LaunchdFields — an emond rule file's root is documented as an
/// ARRAY of rule dictionaries, a shape plist_to_launchd_fields deliberately
/// rejects (it requires a top-level dictionary, launchd's own plist shape).
/// Not exposed in the header: no real-capture emond fixture exists (emond
/// is removed on every host these fixtures were captured from — see
/// test_autoruns_parsers.cpp's own emond test banner), so there is nothing
/// for a test to call this against yet.
bool parse_plist_root(const std::vector<uint8_t>& bytes,
                      yuzu::agent::ScopedCFRef<CFPropertyListRef>& out) {
    yuzu::agent::ScopedCFRef<CFDataRef> data(
        CFDataCreate(kCFAllocatorDefault, bytes.data(), static_cast<CFIndex>(bytes.size())));
    if (!data) return false;
    CFErrorRef raw_error = nullptr;
    out = yuzu::agent::ScopedCFRef<CFPropertyListRef>(CFPropertyListCreateWithData(
        kCFAllocatorDefault, data.get(), kCFPropertyListImmutable, nullptr, &raw_error));
    yuzu::agent::ScopedCFRef<CFErrorRef> error(raw_error);
    return static_cast<bool>(out);
}

/// Extracts the fields parse_emond_rule_plist_fields (autoruns_parsers.hpp)
/// needs from one rule dictionary. emond's rule schema is not documented by
/// Apple beyond example rules shipped historically in /etc/emond.d/rules —
/// `name`/`enabled` are read at the rule's top level and a nested
/// `startcommand` dict's `command` string, matching the shape of Apple's own
/// sample rules; any field absent or in an unexpected CF type is left at
/// EmondRuleFields' own default, never a crash.
EmondRuleFields emond_fields_from_dict(CFDictionaryRef dict) {
    EmondRuleFields fields;
    if (auto name = detail::dict_get_string(dict, CFSTR("name"))) fields.name = *name;
    if (auto enabled = detail::dict_get_bool(dict, CFSTR("enabled"))) {
        fields.enabled_present = true;
        fields.enabled_value = *enabled;
    }
    const void* v = nullptr;
    if (CFDictionaryGetValueIfPresent(dict, CFSTR("startcommand"), &v)) {
        const auto ref = static_cast<CFTypeRef>(v);
        if (ref != nullptr && CFGetTypeID(ref) == CFDictionaryGetTypeID()) {
            const auto start_dict = static_cast<CFDictionaryRef>(ref);
            if (auto cmd = detail::dict_get_string(start_dict, CFSTR("command"))) fields.command = *cmd;
        }
    }
    return fields;
}

/// Outcome of collect_launchd_dir_handle: rows emitted, plus whether
/// kMaxEntriesPerDir was hit with real entries left unread, or a listed
/// plist failed to read/parse for a real reason (AC4: a capped or lossy
/// listing is not a complete one).
struct LaunchdDirOutcome {
    std::size_t rows = 0;
    bool truncated = false;
    bool enumeration_error = false;
    bool file_constrained = false;
    std::string_view file_constrained_reason{};
};

/// Emits one `autorun|` row per successfully-parsed `*.plist` under
/// `dir_path`, all attributed to `source_id`/`scope`. A plist this host's CF
/// implementation cannot parse (PlistError) contributes no row -- never a
/// fabricated one -- but is now counted as a real per-entry constraint
/// (`malformed`), not silently absorbed the way a directory-level read
/// failure already is not.
LaunchdDirOutcome collect_launchd_dir_handle(yuzu::CommandContext& ctx, SourceId source_id,
                                             const DirHandle& dir, const std::string& location,
                                             Scope scope, std::string_view user_override,
                                             std::size_t cap = kMaxEntriesPerDir) {
    std::size_t count = 0;
    bool parse_failed = false;
    const auto walk_outcome =
        walk_plist_dir_handle(dir, [&](const char* name, const std::vector<uint8_t>& bytes,
                                       std::int64_t mtime) {
            auto parsed = plist_to_launchd_fields(std::span<const uint8_t>{bytes.data(), bytes.size()});
            if (!parsed) {
                parse_failed = true;
                return;
            }
            Row row = launchd_row_from_fields(source_id, *parsed, location + "/" + name, scope, mtime);
            if (!user_override.empty()) row.user = std::string{user_override};
            ctx.write_output(format_row(row));
            ++count;
        },
        cap);
    LaunchdDirOutcome outcome{count, walk_outcome.truncated, walk_outcome.enumeration_error,
                              walk_outcome.file_constrained, walk_outcome.file_constrained_reason};
    if (parse_failed && !outcome.file_constrained) {
        outcome.file_constrained = true;
        outcome.file_constrained_reason = "malformed";
    }
    return outcome;
}

/// A whole `collect_*` call's outcome: rows emitted, plus whether ANY
/// directory it opened along the way -- or any per-entry metadata read
/// (#4241) -- hit a real constraint rather than a genuine absence (AC4).
/// Backed by the shared yuzu::shared::ConstraintAccumulator (exact-string
/// dedup, insertion order preserved) rather than this file's former
/// substring-matching accumulation: #4186 introduces suffixed tokens
/// (`row_cap:users`, `row_cap:launchagents`) that are genuine SUBSTRINGS of
/// a plain `row_cap` a sibling call site could also record, which the old
/// `reason.find(token) != npos` dedup would have silently conflated.
struct DirCollectOutcome {
    std::size_t rows = 0;
    yuzu::shared::ConstraintAccumulator acc;
};

void note_dir_constraint(DirCollectOutcome& outcome, std::string_view token) {
    outcome.acc.add_failure(token);
}

DirCollectOutcome collect_launchd_dir(yuzu::CommandContext& ctx, SourceId source_id,
                                      const std::string& dir_path, Scope scope,
                                      std::string_view user_override) {
    DirOpenOutcome open = open_dir_no_follow_checked(dir_path);
    DirCollectOutcome outcome;
    const auto result = collect_launchd_dir_handle(ctx, source_id, open.handle, dir_path, scope, user_override);
    outcome.rows = result.rows;
    if (open.constrained) note_dir_constraint(outcome, open.reason);
    if (result.truncated) note_dir_constraint(outcome, "row_cap");
    if (result.enumeration_error) note_dir_constraint(outcome, "readdir_error");
    if (result.file_constrained) note_dir_constraint(outcome, result.file_constrained_reason);
    return outcome;
}

/// /Users/*/Library/LaunchAgents — one real per-user home per iteration.
/// "Real" is judged by st_uid on the home directory itself (>= 500):
/// non-account entries under /Users (`Shared`, a stray dotfile) are owned by
/// root or otherwise fall below every macOS-assigned real-account uid, so
/// this threshold excludes them without hardcoding names that vary by
/// install. The username reported in each row is the directory's own name
/// (the mac_user_launchagents scope's documented identity), not a
/// getpwuid() lookup — this leg reads files, it does not call into Open
/// Directory.
DirCollectOutcome collect_user_launchagents(yuzu::CommandContext& ctx,
                                            const StatFns& stat_fns = {},
                                            const std::string& users_dir = "/Users",
                                            std::size_t outer_cap = kMaxEntriesPerDir,
                                            std::size_t inner_cap = kMaxEntriesPerDir) {
    DirCollectOutcome outcome;
    DirOpenOutcome users_open = open_dir_no_follow_checked(users_dir);
    if (users_open.constrained) note_dir_constraint(outcome, users_open.reason);
    if (!users_open.handle.valid()) return outcome;
    const auto walk = yuzu::shared::walk_dir_capped(
        users_open.handle.get(), outer_cap, [&](const struct dirent* entry) {
            const std::string_view name(entry->d_name);
            const std::string home = users_dir + "/" + entry->d_name;
            // O_NOFOLLOW on the home directory itself: a symlinked "user" entry
            // under /Users is not a real per-user home this leg will read into.
            const int home_fd = open(home.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
            if (home_fd < 0) {
                const int err = errno;
                if (!is_benign_absent_errno(err))
                    note_dir_constraint(outcome, dir_open_constraint_token(err));
                return true;
            }
            FdHandle home_handle(home_fd);
            struct stat st{};
            if (stat_fns.fstat_fn(home_handle.get(), &st) != 0) {
                // #4241, site 2: a real fstat() failure on an already-open fd
                // is a genuine constraint (AC4), not "this home contributes
                // nothing" -- only a benign ENOENT race is.
                const int stat_err = errno;
                if (const auto token = stat_constraint_token(stat_err)) note_dir_constraint(outcome, *token);
                return true;
            }
            if (st.st_uid < 500) return true; // system/shared account, not a real user home
            // Walk "Library" then "LaunchAgents" as two openat() hops chained
            // from home_fd, each independently O_NOFOLLOW-checked — a single
            // open() on the joined "home/Library/LaunchAgents" string would let
            // the kernel resolve the intermediate "Library" component through
            // normal symlink-following path resolution, escaping confinement to
            // this user's own home (see open_dir_no_follow_at_checked's banner).
            DirOpenOutcome library_open = open_dir_no_follow_at_checked(home_handle.get(), "Library");
            if (library_open.constrained) note_dir_constraint(outcome, library_open.reason);
            if (!library_open.handle.valid()) return true;
            DirOpenOutcome agents_open =
                open_dir_no_follow_at_checked(dirfd(library_open.handle.get()), "LaunchAgents");
            if (agents_open.constrained) note_dir_constraint(outcome, agents_open.reason);
            if (!agents_open.handle.valid()) return true;
            const auto result = collect_launchd_dir_handle(ctx, SourceId::mac_user_launchagents,
                                                            agents_open.handle,
                                                            home + "/Library/LaunchAgents",
                                                            Scope::user, name, inner_cap);
            outcome.rows += result.rows;
            // #4186: this is the INNER (per-user LaunchAgents) walk -- suffixed
            // distinctly from the OUTER /Users walk below so an operator can
            // tell which one actually hit its cap/error, instead of both
            // collapsing to the same ambiguous "row_cap" token once deduped.
            if (result.truncated) note_dir_constraint(outcome, "row_cap:launchagents");
            if (result.enumeration_error) note_dir_constraint(outcome, "readdir_error:launchagents");
            if (result.file_constrained) note_dir_constraint(outcome, result.file_constrained_reason);
            return true;
        });
    if (walk.truncated) note_dir_constraint(outcome, "row_cap:users");
    if (walk.enumeration_error) note_dir_constraint(outcome, "readdir_error:users");
    return outcome;
}

} // namespace

// `collect_macos` itself (below) is excluded when
// YUZU_AUTORUNS_MACOS_UNIT_TEST_INTERNALS_ONLY is defined -- the seam
// test_autoruns_macos_local.cpp uses to #include this TU directly and reach
// the internal-linkage StatFns/stat_constraint_token/walk_dir_names/
// collect_user_launchagents for a constructed-fixture unit test (#4241),
// without pulling collect_macos's own symbol into a second definition. This
// TU never statically links the real plugin either way (test_autoruns_
// macos_local.cpp's other TEST_CASEs load it via PluginHandle::load/dlopen
// at runtime), so a second compilation of the same free functions here
// creates no ODR/duplicate-symbol conflict. Never defined by this TU's own
// (real) build -- meson.build does not set it. Mirrors autoruns_linux.cpp's
// identical seam for YUZU_AUTORUNS_LINUX_UNIT_TEST_INTERNALS_ONLY.
#ifndef YUZU_AUTORUNS_MACOS_UNIT_TEST_INTERNALS_ONLY

int collect_macos(yuzu::CommandContext& ctx, std::string_view filter) {
    // Tracks whether ANY source this leg processed reported CONSTRAINED (not
    // UNSUPPORTED, not plain SUPPORTED) -- ORed into every emit_status call's
    // own return below -- so this leg's return value can surface a real
    // acquisition degradation to do_list's aggregate CC-07 result-status
    // (autoruns_plugin.cpp) instead of it being visible only in the
    // individual `source|` text lines.
    bool any_constrained = false;

    struct SystemDirSpec {
        SourceId id;
        const char* path;
    };
    static constexpr SystemDirSpec kSystemDirs[] = {
        {SourceId::mac_launchdaemons, "/Library/LaunchDaemons"},
        {SourceId::mac_launchagents, "/Library/LaunchAgents"},
        {SourceId::mac_system_launchdaemons, "/System/Library/LaunchDaemons"},
        {SourceId::mac_system_launchagents, "/System/Library/LaunchAgents"},
    };

    for (const auto& spec : kSystemDirs) {
        if (!source_in_filter(filter, spec.id)) {
            any_constrained |=
                emit_status(ctx, spec.id, YUZU_SUPPORT_SUPPORTED, std::nullopt, "filtered");
            continue;
        }
        const auto outcome = collect_launchd_dir(ctx, spec.id, spec.path, Scope::system, {});
        if (outcome.acc.any_failure()) {
            any_constrained |=
                emit_status(ctx, spec.id, YUZU_SUPPORT_CONSTRAINED, outcome.rows, outcome.acc.reason());
        } else {
            any_constrained |=
                emit_status(ctx, spec.id, YUZU_SUPPORT_SUPPORTED, outcome.rows,
                           "launchd_plist_walk");
        }
    }

    if (!source_in_filter(filter, SourceId::mac_user_launchagents)) {
        any_constrained |= emit_status(ctx, SourceId::mac_user_launchagents, YUZU_SUPPORT_SUPPORTED,
                                       std::nullopt, "filtered");
    } else {
        const auto outcome = collect_user_launchagents(ctx);
        if (outcome.acc.any_failure()) {
            any_constrained |= emit_status(ctx, SourceId::mac_user_launchagents,
                                           YUZU_SUPPORT_CONSTRAINED, outcome.rows, outcome.acc.reason());
        } else {
            any_constrained |= emit_status(ctx, SourceId::mac_user_launchagents,
                                           YUZU_SUPPORT_SUPPORTED, outcome.rows,
                                           "launchd_plist_walk");
        }
    }

    // Login Items: no file this leg can read, ever — always this exact
    // status line, unaffected by `sources=` (there is no real read to skip).
    any_constrained |= emit_status(ctx, SourceId::mac_login_items, YUZU_SUPPORT_CONSTRAINED,
                                   std::size_t{0}, "btm_private_database_no_public_api");

    if (!source_in_filter(filter, SourceId::mac_periodic)) {
        any_constrained |= emit_status(ctx, SourceId::mac_periodic, YUZU_SUPPORT_SUPPORTED,
                                       std::nullopt, "filtered");
    } else {
        std::size_t count = 0;
        DirCollectOutcome outcome;
        for (const char* sub : {"daily", "weekly", "monthly"}) {
            const std::string dir_path = std::string{"/etc/periodic/"} + sub;
            const DirConstraint dir_outcome =
                walk_dir_names(dir_path, [&](const char* name, std::int64_t mtime) {
                    Row row;
                    row.source_id = SourceId::mac_periodic;
                    row.catalog_version = kAutorunSourceCatalogVersion;
                    row.location = dir_path;
                    row.entry = name;
                    row.target = dir_path + "/" + name;
                    // periodic(8) executes every script found here unconditionally
                    // -- there is no separate enable/disable flag, so presence
                    // itself is the documented default: Enabled::enabled, not
                    // `unknown` (reserved for a source with no default to reason
                    // from at all).
                    row.enabled = Enabled::enabled;
                    row.scope = Scope::system;
                    row.user = "-";
                    row.signed_state = signed_from_path(row.target);
                    row.mtime = mtime;
                    ctx.write_output(format_row(row));
                    ++count;
                });
            if (dir_outcome.constrained) note_dir_constraint(outcome, dir_outcome.reason);
        }
        if (outcome.acc.any_failure()) {
            any_constrained |= emit_status(ctx, SourceId::mac_periodic, YUZU_SUPPORT_CONSTRAINED,
                                           count, outcome.acc.reason());
        } else {
            any_constrained |= emit_status(ctx, SourceId::mac_periodic, YUZU_SUPPORT_SUPPORTED,
                                           count, "periodic_dir_walk");
        }
    }

    if (!source_in_filter(filter, SourceId::mac_emond)) {
        any_constrained |=
            emit_status(ctx, SourceId::mac_emond, YUZU_SUPPORT_SUPPORTED, std::nullopt, "filtered");
    } else {
        std::size_t count = 0;
        bool any_parse_failed = false;
        const std::string dir_path = "/etc/emond.d/rules";
        const DirConstraint outcome =
            walk_plist_dir(dir_path, [&](const char* name, const std::vector<uint8_t>& bytes,
                                         std::int64_t mtime) {
                const std::string full_path = dir_path + "/" + name;
                yuzu::agent::ScopedCFRef<CFPropertyListRef> root;
                if (!parse_plist_root(bytes, root)) {
                    // A read-but-unparseable rule file (malformed, or a
                    // valid rules plist truncated by kMaxPlistBytes) must
                    // not silently vanish behind a supported status (AC4).
                    any_parse_failed = true;
                    return;
                }

                std::vector<CFDictionaryRef> rule_dicts;
                const CFTypeID type = CFGetTypeID(root.get());
                if (type == CFArrayGetTypeID()) {
                    const auto arr = static_cast<CFArrayRef>(root.get());
                    const CFIndex n = CFArrayGetCount(arr);
                    for (CFIndex i = 0; i < n; ++i) {
                        const auto elem_ref = static_cast<CFTypeRef>(CFArrayGetValueAtIndex(arr, i));
                        if (elem_ref != nullptr && CFGetTypeID(elem_ref) == CFDictionaryGetTypeID())
                            rule_dicts.push_back(static_cast<CFDictionaryRef>(elem_ref));
                    }
                } else if (type == CFDictionaryGetTypeID()) {
                    rule_dicts.push_back(static_cast<CFDictionaryRef>(root.get()));
                }

                for (CFDictionaryRef rule_dict : rule_dicts) {
                    const Row row = parse_emond_rule_plist_fields(emond_fields_from_dict(rule_dict),
                                                                  full_path, mtime);
                    ctx.write_output(format_row(row));
                    ++count;
                }
            });
        std::string reason;
        if (outcome.constrained) reason = std::string{outcome.reason};
        if (any_parse_failed) reason += (reason.empty() ? "" : ",") + std::string{"malformed"};
        if (!reason.empty()) {
            any_constrained |=
                emit_status(ctx, SourceId::mac_emond, YUZU_SUPPORT_CONSTRAINED, count, reason);
        } else {
            any_constrained |= emit_status(ctx, SourceId::mac_emond, YUZU_SUPPORT_SUPPORTED, count,
                                           "emond_rule_plist_walk");
        }
    }

    // Non-zero signals "at least one source reported CONSTRAINED" to
    // do_list's aggregate -- distinct from this function's own success/
    // failure, which this leg has no way to report other than an escaping
    // exception (caught in execute()).
    return any_constrained ? 1 : 0;
}

#endif // !YUZU_AUTORUNS_MACOS_UNIT_TEST_INTERNALS_ONLY

} // namespace yuzu::autoruns

#endif // __APPLE__
