/**
 * privacy_permissions_macos_parsers.hpp -- macOS-only PURE layer: the TCC service -> category
 * table, the `auth_value` decode, the open/prepare outcome classifiers and the per-source row
 * builder. No sqlite3.h, no syscall: privacy_permissions_macos.cpp supplies the real
 * lstat/sqlite3 results (and static_asserts the mirrored SQLite codes below), this file only
 * decides what they MEAN. Separate from privacy_permissions_parsers.hpp (the cross-OS layer),
 * same split as privacy_permissions_win_parsers.hpp.
 *
 * SOURCES: the system TCC.db (rows unqualified -- machine-wide services such as
 * full_disk_access) plus one per-user TCC.db per real home under /Users (rows qualified
 * `<user>\<client>` via qualify_app_id -- camera/microphone grants live there). Each source
 * reports every mapped category: its decoded rows, or an `absent` row when it genuinely holds
 * none, or an `unreadable` row when that category's query step failed.
 */
#pragma once

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "privacy_permissions_parsers.hpp"

namespace yuzu::privacy_permissions::macos {

struct TccService {
    std::string_view service; // literal TCC service identifier
    std::string_view category;
};

// Only three of the four categories this plugin models are TCC services; every other TCC service
// (kTCCServiceContacts, kTCCServiceAppleEvents, kTCCServiceScreenCapture, ...) is out of scope
// by deliberate filter, not a decode failure -- the query never asks for them. `location` is
// NOT here: ADR-3003's platform investigation established macOS Location Services
// is administered by `locationd`, OUTSIDE TCC entirely -- there is no kTCCServiceLocation row
// to query. It ships as its own explicit `unsupported` row instead.
inline constexpr std::array<TccService, 3> kTccServices{{
    {"kTCCServiceCamera", "camera"},
    {"kTCCServiceMicrophone", "microphone"},
    {"kTCCServiceSystemPolicyAllFiles", "full_disk_access"},
}};

/// Commonly-documented `auth_value` mapping across recent macOS releases (0=denied, 2=allowed,
/// 3=limited); any other value is a visible prompt_undetermined rather than a guess. A NULL or
/// non-integer column (nullopt) is `unreadable` -- sqlite3_column_int would silently read it as
/// 0, i.e. a fabricated `denied`. 64-bit: a value past int32 must not wrap onto 0/2/3.
[[nodiscard]] constexpr PermissionState decode_auth_value(std::optional<std::int64_t> v) noexcept {
    if (!v) return PermissionState::unreadable;
    switch (*v) {
    case 0: return PermissionState::denied;
    case 2: return PermissionState::allowed;
    case 3: return PermissionState::allowed; // "limited" -- still a grant, just scoped
    default: return PermissionState::prompt_undetermined;
    }
}

// SQLite primary result codes, mirrored so this header stays sqlite3.h-free;
// privacy_permissions_macos.cpp static_asserts each against the real macro.
inline constexpr int kSqlitePerm = 3;
inline constexpr int kSqliteCantOpen = 14;
inline constexpr int kSqliteAuth = 23;

enum class SourceOutcome { absent, denied, unreadable };

struct SourceFailure {
    SourceOutcome outcome;
    std::string cause; // empty for `absent` (no token -- not a failure)
};

/// The lstat() pre-check on a TCC.db path, run BEFORE the open so a missing file is told apart
/// from a refused one. `lstat_errno` is 0 on success. nullopt = a regular file is there, go
/// ahead and open it.
/// `missing_is_absent`: a per-user TCC.db that does not exist is an honest "this user has no
/// TCC records" (absent); the SYSTEM TCC.db is always present on a supported macOS, so its
/// absence is `unreadable`, never absent. A symlink or other non-regular final component is
/// refused as `unreadable` (the open itself uses O_NOFOLLOW_ANY).
[[nodiscard]] inline std::optional<SourceFailure>
classify_tcc_presence(int lstat_errno, bool is_regular_file, bool missing_is_absent) {
    if (lstat_errno == 0) {
        if (is_regular_file) return std::nullopt;
        return SourceFailure{SourceOutcome::unreadable, "not_regular"};
    }
    if (lstat_errno == ENOENT || lstat_errno == ENOTDIR) {
        if (missing_is_absent) return SourceFailure{SourceOutcome::absent, {}};
        return SourceFailure{SourceOutcome::unreadable, "missing"};
    }
    if (lstat_errno == EPERM || lstat_errno == EACCES)
        return SourceFailure{SourceOutcome::denied, "access_denied"};
    return SourceFailure{SourceOutcome::unreadable, "lstat_errno_" + std::to_string(lstat_errno)};
}

/// A sqlite3_open_v2 / sqlite3_prepare_v2 failure on a file the lstat pre-check already saw
/// as present. SQLITE_AUTH/SQLITE_PERM are refusals -> denied. SQLITE_CANTOPEN is a refusal ONLY
/// when the VFS's own failed syscall (`sys_errno`, from sqlite3_system_errno) was EPERM/EACCES --
/// the SIP/TCC refusal shape, the expected outcome without Full Disk Access; a
/// CANTOPEN for any other reason (ENOENT after a race, EMFILE, ...) is unreadable. Any other code
/// (SQLITE_NOMEM, SQLITE_IOERR, SQLITE_NOTADB, a schema error) is a real fault that gaining FDA
/// would not fix -> unreadable. Pass the EXTENDED code (sqlite3_extended_errcode): only its
/// primary byte is compared.
[[nodiscard]] constexpr SourceOutcome classify_tcc_sqlite_rc(int rc, int sys_errno) noexcept {
    const int primary = rc & 0xff;
    if (primary == kSqliteAuth || primary == kSqlitePerm) return SourceOutcome::denied;
    if (primary == kSqliteCantOpen && (sys_errno == EPERM || sys_errno == EACCES))
        return SourceOutcome::denied;
    return SourceOutcome::unreadable;
}

/// Where in opening one TCC.db a SQLite call failed.
enum class SqliteStage { open, query_only, prepare };

/// The whole-source failure for a SQLite call that failed at `stage`, with cause
/// `<stage>_failed:<sqlite3_errmsg>`. `query_only` (the PRAGMA that makes the connection
/// read-only) never touches the file, so its failure is never a refusal -- always unreadable,
/// and the source is never read without it.
[[nodiscard]] inline SourceFailure classify_tcc_sqlite_failure(SqliteStage stage, int rc,
                                                               int sys_errno,
                                                               std::string_view errmsg) {
    std::string_view prefix = "open_failed:";
    if (stage == SqliteStage::query_only) prefix = "query_only_failed:";
    if (stage == SqliteStage::prepare) prefix = "prepare_failed:";
    const SourceOutcome outcome = stage == SqliteStage::query_only
                                      ? SourceOutcome::unreadable
                                      : classify_tcc_sqlite_rc(rc, sys_errno);
    return {outcome, std::string{prefix}.append(errmsg)};
}

// ── bounded, immutable read of one source ───────────────────────────────

// A per-user TCC.db belongs to the user it describes, so it is hostile input: read by descriptor
// through an immutable URI (no lock, no -journal/-wal/-shm opened or created), refused unless it
// is one quiescent rollback-mode SQLite file, and bounded on every axis.
inline constexpr std::size_t kMaxRowsPerService = 1024; // real max: 6
inline constexpr int kMaxSchemaBytes = 64 * 1024; // schema text and any SQL, until the schema loads
inline constexpr int kMaxValueBytes = 1024;       // after it: real max client 112 B
inline constexpr std::size_t kMaxSourceBytes = 1024 * 1024; // retained client text per source
inline constexpr std::int64_t kMaxDbBytes = 4LL << 20;
inline constexpr std::chrono::milliseconds kRunBudget{10'000};
inline constexpr std::chrono::milliseconds kSourceBudget{500};

struct ReadBounds {
    std::chrono::steady_clock::time_point run_end = std::chrono::steady_clock::now() + kRunBudget;
    std::chrono::steady_clock::duration source_budget = kSourceBudget;
    std::size_t row_cap = kMaxRowsPerService;
};

// Why a category's read stopped short: the token suffix after `<source>:<category>:`.
inline constexpr std::string_view kCutRowCap = "row_cap";
inline constexpr std::string_view kCutTimeout = "timeout";
inline constexpr std::string_view kCutValueOversized = "value_oversized";
inline constexpr std::string_view kCutByteCap = "byte_cap";

inline constexpr std::array<std::string_view, 3> kSidecarSuffixes{"-journal", "-wal", "-shm"};

inline constexpr std::size_t kMaxRunOutputBytes = 16u * 1024u * 1024u;
inline constexpr std::string_view kBudgetExceededToken = "collection:budget_exceeded";

/// Run-wide bound on the row text the sources have produced. Checked between sources, so the one
/// source that crosses it (itself bounded) is kept and no further one is read.
struct OutputBudget {
    std::size_t max_bytes = kMaxRunOutputBytes;
    std::size_t bytes = 0;

    [[nodiscard]] bool exhausted() const noexcept { return bytes >= max_bytes; }
    void charge(std::span<const PermissionRow> rows) noexcept {
        for (const auto& r : rows) bytes += r.app_id.size() + r.raw.size();
    }
};

/// sqlite's URI for `path`: immutable=1 takes no lock and touches no sidecar; `%`, `?` and `#` are
/// the only characters a URI path reads specially.
[[nodiscard]] inline std::string immutable_uri(std::string_view path) {
    std::string out{"file:"};
    for (const char c : path)
        out.append(c == '%' ? "%25" : c == '?' ? "%3F" : c == '#' ? "%23" : std::string_view{&c, 1});
    return out += "?immutable=1";
}

/// A failed open(2) of a file the lstat pre-check saw as present: EPERM/EACCES is the TCC/SIP
/// refusal (denied); ELOOP is O_NOFOLLOW_ANY refusing a symlink anywhere in the path.
[[nodiscard]] inline SourceFailure classify_tcc_open_errno(int err) {
    if (err == ELOOP) return {SourceOutcome::unreadable, "open_failed:symlink"};
    return {err == EPERM || err == EACCES ? SourceOutcome::denied : SourceOutcome::unreadable,
            "open_failed:errno_" + std::to_string(err)};
}

/// The opened descriptor's own fstat: a regular file of plausible size.
[[nodiscard]] inline std::optional<SourceFailure> classify_tcc_file(bool is_regular,
                                                                    std::int64_t size) {
    if (!is_regular) return SourceFailure{SourceOutcome::unreadable, "not_regular"};
    if (size <= 0 || size > kMaxDbBytes)
        return SourceFailure{SourceOutcome::unreadable, "size_out_of_range"};
    return std::nullopt;
}

inline constexpr std::size_t kSqliteHeaderBytes = 100;
inline constexpr std::string_view kSqliteMagic{"SQLite format 3\0", 16};

/// Refuses what an immutable read would silently misread: not SQLite at all, or WAL mode (header
/// bytes 18/19 == 2), whose committed state lives in a -wal this read ignores.
[[nodiscard]] inline std::optional<SourceFailure>
classify_tcc_header(std::span<const unsigned char> h) {
    if (h.size() < kSqliteHeaderBytes ||
        !std::equal(kSqliteMagic.begin(), kSqliteMagic.end(), h.begin(),
                    [](char a, unsigned char b) { return static_cast<unsigned char>(a) == b; }))
        return SourceFailure{SourceOutcome::unreadable, "not_sqlite"};
    if (h[18] == 2 || h[19] == 2) return SourceFailure{SourceOutcome::unreadable, "wal_mode"};
    return std::nullopt;
}

/// The header's file change counter (bytes 24..27, big-endian): bumped by every rollback commit.
[[nodiscard]] constexpr std::uint32_t
header_change_counter(std::span<const unsigned char> h) noexcept {
    std::uint32_t v = 0;
    for (std::size_t i = 24; i < 28 && i < h.size(); ++i) v = v << 8 | h[i];
    return v;
}

/// What identifies the file's state to the read: taken from the descriptor before the first query
/// and again after the last.
struct FileStamp {
    std::uint64_t inode = 0;
    std::int64_t size = 0;
    std::int64_t mtime_sec = 0;
    std::int64_t mtime_nsec = 0;
    std::uint32_t change_counter = 0;
    friend bool operator==(const FileStamp&, const FileStamp&) = default;
};

[[nodiscard]] constexpr bool read_unchanged(const FileStamp& before,
                                            const FileStamp& after) noexcept {
    return before == after;
}

// ── /Users home enumeration ─────────────────────────────────────────────

/// The autoruns collect_user_launchagents rule: a real home is uid 500 or above (below is a
/// system account's directory).
inline constexpr std::uint32_t kMinUserHomeUid = 500;

/// A /Users entry name worth an fstatat at all: not empty, not a dotfile (`.`, `..`,
/// `.localized`, ...).
[[nodiscard]] constexpr bool home_name_eligible(std::string_view name) noexcept {
    return !name.empty() && name.front() != '.';
}

/// Whether one /Users entry is a real per-user home: an eligible name, a directory as seen
/// WITHOUT following a symlink (`is_directory` from an AT_SYMLINK_NOFOLLOW fstatat, so a
/// symlink is never a home), owned by uid >= kMinUserHomeUid (`Shared` and system entries are
/// skipped).
[[nodiscard]] constexpr bool is_user_home_entry(std::string_view name, bool is_directory,
                                                std::uint32_t uid) noexcept {
    return home_name_eligible(name) && is_directory && uid >= kMinUserHomeUid;
}

/// `tcc_db` for the system database, `<user>:tcc_db` for a per-user one -- the subject every
/// whole-source failure token from this leg starts with.
[[nodiscard]] inline std::string tcc_source_key(std::string_view owner) {
    return owner.empty() ? std::string{"tcc_db"} : std::string{owner} + ":tcc_db";
}

[[nodiscard]] inline std::string tcc_row_app_id(std::string_view owner, std::string_view client) {
    return owner.empty() ? std::string{client} : qualify_app_id(owner, client);
}

/// The one row a whole TCC.db source contributes when it could not be read at all: `absent`
/// (per-user file genuinely missing -- no token), or a denied/unreadable failure row whose
/// token is `<source_key>:<cause>`. Category "-": the row stands for every TCC category of
/// that source.
[[nodiscard]] inline PermissionRow tcc_source_failed_row(std::string_view owner,
                                                         const SourceFailure& f,
                                                         yuzu::shared::ConstraintAccumulator& acc) {
    const std::string app_id = tcc_row_app_id(owner, "-");
    if (f.outcome == SourceOutcome::absent)
        return {"macos", app_id, "-", PermissionState::absent, "-", "-", "-", false};
    return failure_row("macos", app_id, "-", f.outcome == SourceOutcome::denied,
                       tcc_source_key(owner) + ":" + f.cause, acc);
}

struct TccGrant {
    std::string client;
    std::optional<std::int64_t> auth_value; // nullopt = NULL / non-integer column
};

/// Deterministic row order (the query has no ORDER BY: on a hostile view it would sort every row
/// before returning the first, defeating the row cap).
inline void sort_grants(std::vector<TccGrant>& grants) {
    std::stable_sort(grants.begin(), grants.end(),
                     [](const TccGrant& a, const TccGrant& b) { return a.client < b.client; });
}

/// One mapped TCC service's query result from one source.
struct TccServiceRead {
    std::string_view category;
    std::vector<TccGrant> grants;
    bool step_failed = false; // sqlite3_step returned something other than ROW/DONE
    bool bind_failed = false; // sqlite3_bind_text failed -- the query never ran
    std::string_view cut{};   // a kCut* bound stopped the read; `grants` keeps what came before
};

/// Appends one successfully-opened source's rows: every decoded grant; an `unreadable` row
/// (token `<source_key>:<category>:query_bind_failed` / `...:query_step_failed` / `...:<kCut*>`)
/// for a category whose query could not be bound, whose step failed or that hit a bound -- even
/// when some of its rows were already read, since the set is incomplete; and an `absent` row for
/// a category the source cleanly holds nothing for. A grant whose auth_value could not
/// be read is an `unreadable` row with token `<source_key>:<category>:auth_value_unreadable`.
inline void append_tcc_source_rows(std::string_view owner, std::span<const TccServiceRead> reads,
                                   std::vector<PermissionRow>& rows,
                                   yuzu::shared::ConstraintAccumulator& acc) {
    const std::string key = tcc_source_key(owner);
    for (const auto& read : reads) {
        if (read.bind_failed) {
            rows.push_back(failure_row("macos", tcc_row_app_id(owner, "-"), read.category, false,
                                       key + ":" + std::string{read.category} +
                                           ":query_bind_failed",
                                       acc));
            continue;
        }
        for (const auto& g : read.grants) {
            if (!g.auth_value) {
                rows.push_back(failure_row("macos", tcc_row_app_id(owner, g.client), read.category,
                                           false,
                                           key + ":" + std::string{read.category} +
                                               ":auth_value_unreadable",
                                           acc));
                continue;
            }
            rows.push_back({"macos", tcc_row_app_id(owner, g.client), read.category,
                            decode_auth_value(g.auth_value), std::to_string(*g.auth_value), "-", "-",
                            false});
        }
        if (!read.cut.empty()) {
            rows.push_back(failure_row("macos", tcc_row_app_id(owner, "-"), read.category, false,
                                       key + ":" + std::string{read.category} + ":" +
                                           std::string{read.cut},
                                       acc));
        } else if (read.step_failed) {
            rows.push_back(failure_row("macos", tcc_row_app_id(owner, "-"), read.category, false,
                                       key + ":" + std::string{read.category} +
                                           ":query_step_failed",
                                       acc));
        } else if (read.grants.empty()) {
            rows.push_back({"macos", tcc_row_app_id(owner, "-"), read.category,
                            PermissionState::absent, "-", "-", "-", false});
        }
    }
}

} // namespace yuzu::privacy_permissions::macos
