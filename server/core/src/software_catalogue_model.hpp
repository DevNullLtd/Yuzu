#pragma once

/// @file software_catalogue_model.hpp
/// The ONE pure model behind the software catalogue's REST routes, built to be shared by every
/// other surface that serves the same data (for example the `/inventory` Software page):
/// query-parameter parsing, the scope push-down rule, audit targets, opaque keyset cursors, the
/// generation-skew decision, KPI derivation and the JSON/CSV shaping. No httplib, no MCP, no
/// libpq - every transport shapes its answer through these functions so the wire shapes cannot
/// drift (docs/api-twin-recipe.md Rule 1).
///
/// Cursors are OPAQUE, not authenticated: a well-formed hand-made head cursor is accepted. That
/// is harmless only because every page is audited (success on EVERY call, continuation pages
/// tagged `page=continuation`). The catalogue cursor is bound to the filter set AND to the
/// rollup generation (`refreshed_at`, 1 s granularity); a mismatch is a 400, never a silent
/// restart.

#include "data_export.hpp"
#include "software_catalog_rules.hpp"
#include "software_inventory_store.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::software_catalogue {

// ── Bounds ───────────────────────────────────────────────────────────────────

inline constexpr std::int64_t kCatalogueDefaultLimit = 100;
inline constexpr std::int64_t kCataloguePageMax = 1000;
inline constexpr std::int64_t kVersionsDefaultLimit = 200;
inline constexpr std::int64_t kVersionsMax = 1000;
inline constexpr std::int64_t kExportCap = 10000;
inline constexpr std::size_t kCursorMaxBytes = 2048; ///< longest cursor token accepted; a longer one is refused
inline constexpr std::int64_t kStaleWindowSecs = 172800; ///< 48 h
inline constexpr std::size_t kSourceMaxBytes = 256;
/// Largest `limit` one `software_catalog` read honours (the store's own hard ceiling).
inline constexpr std::int64_t kCatalogReadMax = 2000;

inline constexpr std::string_view kTitlesCsvHeader =
    "name,publisher,installs,versions,ecosystems,kinds,newest_version";

// ── Parameters ───────────────────────────────────────────────────────────────

using Params = std::multimap<std::string, std::string>;

struct CatalogueRequest {
    SoftwareCatalogQuery query;
    std::string cursor;
    std::string format{"json"}; ///< "json" | "csv"
};

/// Keys: q, kind, ecosystem, source, agent_id, versions_min, limit, cursor, format. A repeated
/// key, a non-integer limit/versions_min, an unknown format or an oversize cursor is refused (the
/// error is the 400 message). Empty kind/ecosystem/source mean "no filter". `limit` is clamped;
/// for format=csv it is the TOTAL export cap (default and ceiling kExportCap), and a `cursor`
/// is refused (an export is one whole walk with no continuation). Unknown keys are ignored.
[[nodiscard]] std::expected<CatalogueRequest, std::string> parse_catalogue_params(const Params& p);

struct VersionsRequest {
    SoftwareVersionsQuery query;
};
/// `name` is required. Same repeated-key rule.
[[nodiscard]] std::expected<VersionsRequest, std::string> parse_versions_params(const Params& p);

// ── Audit targets ────────────────────────────────────────────────────────────

[[nodiscard]] std::string audit_target(const SoftwareCatalogQuery& q);
[[nodiscard]] std::string audit_target(const SoftwareVersionsQuery& q);

// ── Cursors ──────────────────────────────────────────────────────────────────

enum class CursorError { kMalformed, kFilterMismatch, kStale };

/// Wire message for a refused cursor (an HTTP 400 on the REST routes).
[[nodiscard]] std::string_view cursor_error_message(CursorError e);

[[nodiscard]] std::string filter_fingerprint(const SoftwareCatalogQuery& q);

/// `c1:<fp16>:<refreshed_at>:<b64url(installs 0x1F name)>`. The host path passes 0.
[[nodiscard]] std::string encode_catalogue_cursor(const SoftwareCatalogRow& last,
                                                  std::string_view fp, std::int64_t refreshed_at);
/// Refusal order: malformed -> filter mismatch -> stale.
[[nodiscard]] std::expected<SoftwareCatalogCursor, CursorError>
decode_catalogue_cursor(std::string_view token, std::string_view fp, std::int64_t refreshed_at);

// ── KPIs ─────────────────────────────────────────────────────────────────────

struct Coverage {
    std::optional<std::int64_t> connected; ///< connected-agent registry size; null when unwired
    std::optional<std::int64_t> stale;     ///< devices not seen in 48 h; null when the read degraded
};

struct KpiFigures {
    CatalogRollupMeta meta;
    Coverage coverage;
    bool building{false}; ///< refreshed_at == 0 (never computed)
    int windows_pct{0}, macos_pct{0}, linux_pct{0}, other_pct{0};
    std::optional<int> stay_current_pct;
    double sprawl_pct{0.0};
    std::int64_t avg_installs_per_device{0};
};

[[nodiscard]] KpiFigures derive_kpis(const CatalogRollupMeta& meta, const Coverage& coverage);
[[nodiscard]] nlohmann::json kpis_json(const KpiFigures& k);

// ── JSON ─────────────────────────────────────────────────────────────────────

[[nodiscard]] nlohmann::json catalogue_row_json(const SoftwareCatalogRow& r, bool omit_newest);
/// `next_cursor` non-empty -> string, else null. `kpis` nullopt -> null.
[[nodiscard]] nlohmann::json
catalogue_response_json(const std::vector<SoftwareCatalogRow>& rows,
                        const SoftwareCatalogTotals& totals, const std::optional<KpiFigures>& kpis,
                        std::string_view next_cursor, bool omit_newest,
                        std::int64_t devices_omitted);
[[nodiscard]] nlohmann::json version_row_json(const SoftwareVersionCount& v, bool omit_newest);
[[nodiscard]] nlohmann::json versions_response_json(std::string_view name,
                                                    const std::vector<SoftwareVersionCount>& rows,
                                                    bool truncated, bool omit_newest);

/// Serialise without ever throwing on a stray invalid-UTF-8 byte (replaced with U+FFFD).
[[nodiscard]] std::string dump_safe(const nlohmann::json& j);

// ── CSV ──────────────────────────────────────────────────────────────────────

[[nodiscard]] std::string titles_csv(const std::vector<SoftwareCatalogRow>& rows, bool omit_newest);

using CatalogueReader =
    std::function<std::optional<std::vector<SoftwareCatalogRow>>(const SoftwareCatalogQuery&)>;
/// One titles export: the CSV body, whether the cap cut the walk short, and the number of data
/// rows in it (the audit's `rows=`; a cell holding a newline must not inflate it).
struct TitlesExport {
    std::string csv;
    bool truncated{false};
    std::int64_t rows{0};
};

/// Titles export: loops `read` with the in-process keyset cursor (each read asks for
/// min(cap - collected, kCatalogReadMax) rows) and returns a TitlesExport (csv, truncated, rows);
/// `truncated` is set when the cap cut the walk short. nullopt when any read degrades (never a
/// partial body).
[[nodiscard]] std::optional<TitlesExport> titles_export(const CatalogueReader& read,
                                                        SoftwareCatalogQuery q, std::int64_t cap,
                                                        bool omit_newest);

// ── One consistent catalogue read ────────────────────────────────────────────

/// The three store reads a catalogue page needs, injected so the generation-skew logic is pure
/// and unit-tested with fakes (the shells bind them to the SoftwareInventoryStore).
struct CatalogueReads {
    std::function<std::optional<CatalogRollupMeta>()> meta;
    CatalogueReader rows;
    std::function<std::optional<SoftwareCatalogTotals>(const SoftwareCatalogQuery&)> totals;
};

struct CataloguePage {
    std::vector<SoftwareCatalogRow> rows;
    SoftwareCatalogTotals totals;
    std::optional<CatalogRollupMeta> meta; ///< fleet path only (nullopt on the host path)
    std::string next_cursor;               ///< non-empty iff rows.size() == query.limit
};

/// Reads {meta, rows, totals, meta} for one catalogue page. Fleet path: the rollup generation
/// brackets the reads; a move on a first page re-reads ONCE. The cursor is decoded against the
/// generation read first. Host path (query.agent_id set): no meta, generation 0.
/// Error: nullopt = degraded (any read returned nullopt, or the generation moved twice: 503 +
/// retry); a CursorError = the cursor was refused (malformed / other filter set / stale: the
/// generation moved under a continuation page, restart from page one) -> 400.
[[nodiscard]] std::expected<CataloguePage, std::optional<CursorError>>
read_catalogue_page(const CatalogueReads& io, const CatalogueRequest& rq);

/// Titles export: the whole walk is bracketed by the generation (restart once, then
/// degraded = nullopt, never a partial body). `rq.query.limit` is the TOTAL row cap.
[[nodiscard]] std::optional<TitlesExport>
read_titles_export(const CatalogueReads& io, const CatalogueRequest& rq, bool omit_newest);

} // namespace yuzu::server::software_catalogue
