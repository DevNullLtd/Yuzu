#pragma once

/// @file crypto_library_model.hpp
/// The ONE pure model behind the `/crypto` crypto-library-presence surface (slice 1), shared by
/// REST, MCP and the dashboard fragments so the wire shapes cannot drift: the curated
/// package-name table and its classifier, the SQL LIKE patterns derived from that same table,
/// query-parameter parsing (REST clamps, MCP refuses), filter-bound keyset cursors and the JSON
/// shapers. No httplib, no MCP, no libpq, no store types.
///
/// MECHANISM, not interpretation (ADR-1005 D2, like ADR-0024's `product_normalize`): the table
/// maps a package name to a library family by deterministic name matching and the surface
/// reports presence and versions only. It never labels a library or version good, bad, current
/// or out of date; that is engine territory behind the ADR-0032 interlock. Matching happens in
/// SQL from patterns derived from this table - there is NO second copy of the rules.
///
/// Editing the table bumps `kCryptoTableVersion`, which every summary returns as
/// `table_version` so a client can tell which mapping produced an answer.
///
/// Cursors are OPAQUE, not authenticated (same posture as the software catalogue's); every page
/// served is audited and a cursor is bound to the filter set, never to the scope.

#include "crypto_types.hpp"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::crypto_library {

inline constexpr int kCryptoTableVersion = 2;

// ── Bounds ───────────────────────────────────────────────────────────────────

inline constexpr std::int64_t kDefaultLimit = 100;
inline constexpr std::int64_t kPageMax = 1000;
/// `version` and `ecosystem` are bounded at the INGEST per-field bound (inventory_ingestion.cpp
/// kMaxFieldLen, 1024): any bucket the summary can emit must be drillable, so a tighter bound
/// here would strand a long-version chip. A comment-coordinated pair - raise both or neither.
inline constexpr std::size_t kEcosystemMaxBytes = 1024;
inline constexpr std::size_t kVersionMaxBytes = 1024;
inline constexpr std::size_t kCursorMaxBytes = 2048;
/// Version buckets shown per family; the rest set `versions_truncated`.
inline constexpr std::size_t kMaxVersionsPerFamily = 50;
/// Each emitted package name is cut to this many bytes (UTF-8 safe; a cut name ends in U+2026).
inline constexpr std::size_t kNameMaxBytes = 256;
/// Byte budget of the whole serialised summary (about 256 KiB, plus at most one first bucket
/// per family that is always kept: worst case about 300 KB): version buckets beyond it are dropped (the
/// family sets `versions_truncated`, the summary `result_truncated`). One agent reporting
/// thousands of versions/long names cannot grow the response (REST, MCP and the fragment all
/// shape through finish_summary) or silently evict - the cut is always flagged.
inline constexpr std::size_t kSummaryByteBudget = 256 * 1024;

// ── The curated table ────────────────────────────────────────────────────────

/// Length of the literal lead the store matches before the LIKE; every rule is at least this long
/// (static_assert in the .cpp).
inline constexpr std::size_t kLeadChars = 3;

struct Family {
    std::string_view id;
    std::string_view display;
};

enum class MatchKind { kExact, kPrefix };

/// `value` is lowercase; matching is against the lowercased package name.
struct MatchRule {
    std::string_view family_id;
    MatchKind kind;
    std::string_view value;
};

[[nodiscard]] std::span<const Family> families();
[[nodiscard]] std::span<const MatchRule> rules();
[[nodiscard]] const Family* find_family(std::string_view id);

/// The family id a package name belongs to (case-insensitive), or nullopt. The first matching
/// rule wins; the table is built so no package matches two families.
[[nodiscard]] std::optional<std::string_view> classify(std::string_view package_name);

/// LIKE pattern for one rule: `\`, `%` and `_` escaped, `%` appended for a prefix rule.
[[nodiscard]] std::string like_pattern(const MatchRule& r);

/// Parallel arrays for the store (`patterns[i]` labels as `labels[i]`), every rule of every
/// family, or only the named family's.
/// `leads[i]` is the first kLeadChars characters of rule i's literal (lowercase ASCII): the
/// store pre-filters candidate names by it before the LIKE.
struct SqlPatterns {
    std::vector<std::string> patterns;
    std::vector<std::string> labels;
    std::vector<std::string> leads;
};
[[nodiscard]] SqlPatterns sql_patterns(std::optional<std::string_view> family = std::nullopt);

// ── Parameters ───────────────────────────────────────────────────────────────

using Params = std::multimap<std::string, std::string>;

/// Keys: family, ecosystem. A key repeated with differing values (identical pairs collapse in
/// the HTTP layer), an unknown family id, non-UTF-8 text or an over-long value is refused (the
/// error is the 400 message). An empty `family` means "no filter"; a PRESENT `ecosystem`, even
/// empty, is the exact ecosystem (the empty one is real: pre-v2 rows carry none) - absent means
/// any. Unknown keys are ignored.
[[nodiscard]] std::expected<CryptoSummaryQuery, std::string> parse_summary_params(const Params& p);

/// Keys: family (required), version, ecosystem, cursor, limit. `limit` is clamped to
/// [1, kPageMax]; a value that is not a plain decimal integer (non-numeric, out of int64 range,
/// a signed form such as "+5") is refused. A present `version` or `ecosystem`, even empty, is the
/// exact bucket (the empty one is real: some rows carry none). Same refusals as above.
[[nodiscard]] std::expected<CryptoDevicesQuery, std::string> parse_devices_params(const Params& p);

/// MCP's STRICT argument checks (REST clamps instead): a wrong JSON type, an unknown family,
/// an over-long string or an out-of-range `limit` is refused rather than clamped. nullopt =
/// acceptable; otherwise the kInvalidParams message.
[[nodiscard]] std::optional<std::string> strict_summary_args_error(const nlohmann::json& args);
[[nodiscard]] std::optional<std::string> strict_devices_args_error(const nlohmann::json& args);

// ── Audit targets ────────────────────────────────────────────────────────────

[[nodiscard]] std::string audit_target(const CryptoSummaryQuery& q);
[[nodiscard]] std::string audit_target(const CryptoDevicesQuery& q);

/// The ONE audit detail key set of both verbs, on every transport:
/// `[cid=<cid> ]tv=<table_version> family=<f|all> rows=<n>[ page=continuation]`. `cid` empty
/// (the MCP path mints none) omits the `cid=` key. `rows` = families for the summary, package
/// rows for the drill.
[[nodiscard]] std::string audit_detail(std::string_view cid, std::string_view family,
                                       std::size_t rows, bool continuation);
/// The failure-row twin: `[cid=<cid> ]tv=<table_version> store degraded`.
[[nodiscard]] std::string audit_detail_degraded(std::string_view cid);

// ── Cursors ──────────────────────────────────────────────────────────────────

/// kFilterMismatch covers a different filter set AND a different table version (the version is
/// part of the fingerprint): either way the walk must restart without a cursor.
enum class CursorError { kMalformed, kFilterMismatch };

[[nodiscard]] std::string_view cursor_error_message(CursorError e);

/// The keyset position of the last row served: (agent_id, package_name, install_id).
struct CursorPos {
    std::string agent_id;
    std::string name;
    std::int64_t install_id{0};
};

/// Bound to family + version + ecosystem + the table version (never to the scope or the
/// limit). A present-empty version/ecosystem differs from an absent one. `table_version`
/// defaults to the current table; a parameter only so a test can mint another version's cursor.
[[nodiscard]] std::string devices_fingerprint(const CryptoDevicesQuery& q,
                                              int table_version = kCryptoTableVersion);

/// `k1:<fp16>:<b64url(length-prefixed {agent_id, name, install_id})>`.
[[nodiscard]] std::string encode_cursor(const CursorPos& at, std::string_view fp);
/// Refusal order: malformed -> filter mismatch.
[[nodiscard]] std::expected<CursorPos, CursorError> decode_cursor(std::string_view token,
                                                                  std::string_view fp);

// ── Assembly + JSON ──────────────────────────────────────────────────────────

/// Normalise a summary the local API filled in: drop zero-device families, fill display names,
/// order versions (device_count desc, version, ecosystem) and cap them at kMaxVersionsPerFamily,
/// cut every package name to kNameMaxBytes, order families (device_count desc, id), then fit the
/// serialised size into kSummaryByteBudget (every family keeps its first bucket, so the budget
/// is exceeded by at most those 12 buckets). Whenever a
/// family's version list is cut - by the per-family cap, by the budget, or emptied by the
/// store's row cap - `versions_truncated` is set; a budget cut also sets `result_truncated`.
void finish_summary(CryptoSummary& s);

[[nodiscard]] nlohmann::json summary_json(const CryptoSummary& s);
[[nodiscard]] nlohmann::json devices_json(const CryptoDevicesPage& p);

/// Serialise without ever throwing on a stray invalid-UTF-8 byte (replaced with U+FFFD).
[[nodiscard]] std::string dump_safe(const nlohmann::json& j);

} // namespace yuzu::server::crypto_library
