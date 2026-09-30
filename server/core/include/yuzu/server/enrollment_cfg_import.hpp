#pragma once

/**
 * enrollment_cfg_import.hpp — one-time import of the legacy per-replica
 * enrollment state files into Postgres (WS-6 slice 6.2, ADR-2002 section 8).
 *
 * Before 6.2 the server kept enrollment tokens and pending-agent approvals in
 * two flat files, `enrollment-tokens.cfg` and `pending-agents.cfg`. Slice 6.2
 * moves that state into AuthDB (schema `auth`) so every replica shares it; this
 * is the ONE named exception to the auth store's fresh-start/no-backfill rule
 * (a fleet's outstanding tokens and its approve/deny decisions are operator work
 * that must survive the upgrade).
 *
 * Layers (each independently testable):
 *  1. PURE parsing + fingerprinting (`parse_*_cfg`, `content_fingerprint`) - no
 *     I/O, never throws. Tolerant per line: a garbled line is skipped and counted,
 *     never fatal (the deleted loaders threw std::stoi out of load_config).
 *  2. `AuthDB::import_legacy_tokens` / `import_legacy_pending` - the DB write, ONE
 *     transaction under an advisory lock (auth_db.cpp), marker row stamped in the
 *     SAME transaction as the imported rows.
 *  3. `run_legacy_enrollment_import` - file location, read, rename-after-commit,
 *     logging, metrics; invoked from Server::create right after set_auth_db and
 *     BEFORE any listener binds (never from a main.cpp one-shot).
 *
 * The file formats (git show 257bfb338:server/core/src/auth.cpp, save_/load_tokens
 * and save_/load_pending):
 *   enrollment-tokens.cfg  token_id:token_hash:label:max_uses:use_count:created_epoch:expires_epoch:revoked
 *                          (expires 0 = never; revoked 0/1)
 *   pending-agents.cfg     agent_id:hostname:os:arch:version:requested_epoch:status
 *                          (status pending|approved|denied)
 * with '#' comment/header lines ("# Version: 1").
 */

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}
namespace yuzu::server {
class AuthDB;
}

namespace yuzu::server::enrollment_import {

inline constexpr std::string_view kTokensFileName = "enrollment-tokens.cfg";
inline constexpr std::string_view kPendingFileName = "pending-agents.cfg";
/// `auth.import_meta.key` for each file KIND. Each kind has its own marker.
inline constexpr std::string_view kTokensMarkerKey = "enrollment-tokens.cfg";
inline constexpr std::string_view kPendingMarkerKey = "pending-agents.cfg";
/// Files larger than this are refused (a 32 MiB token file is ~300k rows: far
/// beyond any real fleet, so this only bounds a corrupt/hostile file).
inline constexpr std::size_t kMaxImportFileBytes = 32u * 1024u * 1024u;

/// One parsed, VALIDATED enrollment-tokens.cfg row. `token_hash` is a lowercase
/// 64-hex SHA-256; the file's own token_id column is not carried (the id is
/// always the hash prefix - the store derives/disambiguates it).
struct LegacyToken {
    std::string token_hash;
    std::string label;
    int max_uses{0};   ///< 0 = unlimited
    int use_count{0};
    std::int64_t created_epoch{0};
    std::int64_t expires_epoch{0}; ///< 0 = never
    bool revoked{false};
};

/// One parsed, VALIDATED pending-agents.cfg row.
struct LegacyPending {
    std::string agent_id;
    std::string hostname;
    std::string os;
    std::string arch;
    std::string agent_version;
    std::int64_t requested_epoch{0};
    std::string status; ///< exactly "pending" | "approved" | "denied"
};

struct ParseStats {
    std::size_t data_lines{0}; ///< non-empty, non-comment lines seen
    std::size_t garbled{0};    ///< skipped: wrong field count / bad number / oversize / NUL / bad enum
    std::size_t recovered{0};  ///< kept after unambiguous ':'-in-label recovery (tokens only)
    bool unsupported_version{false}; ///< a "# Version: N" header with N != 1 was seen
};

struct ParsedTokens {
    std::vector<LegacyToken> rows;
    ParseStats stats;
};
struct ParsedPending {
    std::vector<LegacyPending> rows;
    ParseStats stats;
};

/// Tolerant parsers: never throw, never abort on a bad line.
[[nodiscard]] ParsedTokens parse_tokens_cfg(std::string_view content);
[[nodiscard]] ParsedPending parse_pending_cfg(std::string_view content);

/// Lowercase-hex SHA-256 of the raw file bytes - the marker fingerprint.
[[nodiscard]] std::string content_fingerprint(std::string_view bytes);

/// Per-row outcome counts from the DB write.
struct ImportCounts {
    std::size_t imported{0};
    std::size_t skipped_existing{0}; ///< PG already had the row: PG state wins
    std::size_t id_disambiguated{0}; ///< token kept under a longer token_id (id collision)
    std::size_t failed{0};           ///< could not be placed (id space exhausted) - counted, not fatal
};

enum class ImportStatus : std::uint8_t {
    imported,             ///< marker absent: rows inserted + marker stamped
    already_imported,     ///< marker present, SAME fingerprint: nothing done
    fingerprint_mismatch, ///< marker present, DIFFERENT fingerprint: refused, nothing written
};

struct ImportDbResult {
    ImportStatus status{ImportStatus::imported};
    ImportCounts counts;
    std::string stored_fingerprint; ///< the marker's fingerprint when one existed
};

// -- Orchestrator -------------------------------------------------------------

/// Where a pre-6.2 install could have left the files. The OLD code loaded from
/// the config directory (parent of the auth config file) first, then - when
/// --data-dir was set - reloaded from the data dir (which replaced the map only
/// if the file existed there) and wrote every later save to the data dir. So both
/// can hold a file; the data-dir one is what the old code loaded last and wins.
struct Locations {
    std::filesystem::path data_dir;   ///< --data-dir (may be empty)
    std::filesystem::path config_dir; ///< auth config file's parent (may be empty)
};

struct Options {
    /// Best-effort rename hook (default: std::filesystem::rename). Injectable so a
    /// test can prove a rename failure is tolerated.
    std::function<bool(const std::filesystem::path& from, const std::filesystem::path& to)>
        rename_fn;
};

enum class Outcome : std::uint8_t {
    imported,
    already_imported,
    fingerprint_mismatch,
    absent,
    error,
};

/// What happened for one file kind. Retained so Server can emit the audit event
/// once the audit store exists (it is constructed after the auth store).
struct KindReport {
    std::string kind; ///< "tokens" | "pending"
    Outcome outcome{Outcome::absent};
    ImportCounts counts;
    ParseStats parse;
    std::string fingerprint;
    std::filesystem::path source;      ///< file examined (empty if absent)
    std::filesystem::path other_copy;  ///< the older config-dir copy left untouched, if any
    bool renamed{false};
    std::string detail; ///< human-readable reason for error / mismatch
};

struct RunResult {
    std::vector<KindReport> reports;
    bool fatal{false}; ///< a PG/read error with a file present: the caller MUST refuse to start
};

/// Import both legacy files (each its own marker). NEVER throws. `metrics` may be
/// null. See the header comment for the semantics; the load-bearing ones:
///  - a missing file stamps NOTHING (a later boot with the file present imports);
///  - marker + equal fingerprint => skip (+ best-effort rename to <name>.imported);
///  - marker + DIFFERENT fingerprint => refuse, CRITICAL log + metric, file left,
///    boot continues;
///  - a PG/read error with the file present => `fatal`.
[[nodiscard]] RunResult run_legacy_enrollment_import(AuthDB& db, const Locations& where,
                                                     yuzu::MetricsRegistry* metrics,
                                                     const Options& opts = {});

[[nodiscard]] const char* to_string(Outcome o) noexcept;

} // namespace yuzu::server::enrollment_import
