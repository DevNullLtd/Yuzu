#pragma once

/// @file software_export_stream.hpp
/// The pure core of the streamed installed-software export (SAM-36, roadmap 3.3):
/// `GET /api/v1/inventory/software/export?format=jsonl|csv`. No httplib, no libpq, no clock: the
/// route module injects every read, so the parse, the chunk formatting and the concurrency clamp
/// are testable from fixture data.
///
/// Rules this file owns (each stated once, here):
///  * REQUEST: the list route's filters (software_list::parse_list_params) plus a REQUIRED
///    `format` of `jsonl` or `csv`. `cursor` and `limit` are refused: a stream has no pages of its
///    own to resume (the server walks its own cursors), and a page-style row cap belongs to the in-memory
///    formats, not to a stream.
///  * ROWS: one row is exactly the list route's row (`list_row_json`, or the list CSV writer, which
///    neutralises formula cells through data_export.hpp). The two formats carry the same columns as
///    the list route's JSON and CSV, so a consumer can move between them.
///  * CSV: the header is written once, in the first chunk, even when the stream has no rows.
///    JSONL: one JSON object per line, nothing for an empty result.
///  * CAP: at most `--inventory-export-concurrency` streams are open at once. A stream holds an HTTP
///    worker for its whole life, so the cap bounds how many workers exports can pin. It is NOT
///    counted here: each stream is one lease from the server's one StreamBudget
///    (`SseSurface::kSoftwareExport`, ADR-0034), and this file only owns the accepted range.

#include "software_list_model.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::server::software_export {

enum class ExportFormat { jsonl, csv };

/// `--inventory-export-concurrency`: default and the accepted range.
inline constexpr int kDefaultConcurrency = 2;
inline constexpr int kMinConcurrency = 1;
inline constexpr int kMaxConcurrency = 16;

/// Rows per store read: the list route's page ceiling.
inline constexpr int kPageRows = static_cast<int>(software_catalogue::kCataloguePageMax);

/// Wall-clock bound on one stream. A stream that outlives it is aborted (the transfer is cut
/// without its terminating chunk), so a sparse wide scope cannot hold a worker indefinitely.
inline constexpr std::int64_t kExportMaxSeconds = 900;

/// Size limits on one stream (`--inventory-export-max-rows`, `--inventory-export-max-bytes`): a
/// stream that would pass either is aborted, like the deadline, so a huge fleet cannot be asked for
/// one unbounded file. Both apply to JSONL and CSV alike; the bytes counted are the body bytes
/// written (the CSV header included). The row floor is one page, so a smaller row cap could never
/// admit a page; the byte floor (1 MiB) is far above a normal 1000-row page, and a page that did not
/// fit would be cut on its first chunk (the cap is a true maximum).
inline constexpr std::int64_t kDefaultMaxRows = 5'000'000;
inline constexpr std::int64_t kDefaultMaxBytes = std::int64_t{1} << 30; // 1 GiB
inline constexpr std::int64_t kMinMaxRows = kPageRows;
inline constexpr std::int64_t kMinMaxBytes = std::int64_t{1} << 20;     // 1 MiB

struct Limits {
    std::int64_t max_rows{kDefaultMaxRows};
    std::int64_t max_bytes{kDefaultMaxBytes};
};

/// Applied at registration so a caller that skipped the flag validator (a test, a future call site)
/// can never turn a limit into "none": 0 or a negative reads as the floor. The ceilings are the
/// flags' own range (main.cpp).
[[nodiscard]] constexpr Limits clamp_limits(Limits l) noexcept {
    l.max_rows = std::max(l.max_rows, kMinMaxRows);
    l.max_bytes = std::max(l.max_bytes, kMinMaxBytes);
    return l;
}

/// True when writing `add_rows` more rows and `add_bytes` more bytes on top of what is already
/// written stays inside both limits. A cap is a true maximum: the chunk that would pass it is not
/// written.
[[nodiscard]] constexpr bool within_limits(const Limits& l, std::int64_t rows_written,
                                           std::int64_t bytes_written, std::size_t add_rows,
                                           std::size_t add_bytes) noexcept {
    return rows_written + static_cast<std::int64_t>(add_rows) <= l.max_rows &&
           bytes_written + static_cast<std::int64_t>(add_bytes) <= l.max_bytes;
}

/// The 503 retry hint when the export cap or the server's held-open budget is full.
inline constexpr int kRetryAfterMs = 5000;

/// The closed label sets of yuzu_server_software_export_total{format,result}, pre-seeded at boot.
inline constexpr std::array<ExportFormat, 2> kFormats{ExportFormat::jsonl, ExportFormat::csv};
inline constexpr std::array<std::string_view, 5> kResults{"completed", "degraded", "deadline",
                                                           "aborted", "limit"};
/// The closed label set of yuzu_server_software_export_rejected_total{reason}, pre-seeded at boot:
/// which limit refused the stream, so the operator knows which flag to raise.
/// `export_concurrency_cap` = --inventory-export-concurrency (StreamBudget's per-key reject: every
/// export lease shares one key, so the per-key cap is the export cap); `global_stream_cap` =
/// --max-sse-streams (StreamBudget's `kRejectGlobal`, spelled identically).
inline constexpr std::array<std::string_view, 2> kRejectReasons{"export_concurrency_cap",
                                                                 "global_stream_cap"};

[[nodiscard]] constexpr std::string_view format_name(ExportFormat f) noexcept {
    return f == ExportFormat::csv ? "csv" : "jsonl";
}
[[nodiscard]] constexpr std::string_view content_type(ExportFormat f) noexcept {
    return f == ExportFormat::csv ? "text/csv; charset=utf-8" : "application/x-ndjson";
}
[[nodiscard]] constexpr std::string_view file_name(ExportFormat f) noexcept {
    return f == ExportFormat::csv ? "software-installs.csv" : "software-installs.jsonl";
}

struct ExportRequest {
    ExportFormat format{ExportFormat::jsonl};
    /// The parsed list request. `base.cursor` stays empty and `base.query.limit` is kPageRows; the
    /// route walks `base.query` in process, keeping its own resume position between store reads.
    software_list::ListRequest list;
};

/// The error is the 400 message. A repeated key keeps the first value (the list parser's rule).
[[nodiscard]] inline std::expected<ExportRequest, std::string>
parse_export_params(const software_list::Params& p) {
    const auto has = [&p](const char* k) { return p.find(k) != p.end(); };
    const auto fmt = p.find("format");
    if (fmt == p.end() || fmt->second.empty())
        return std::unexpected("format is required (expected jsonl or csv)");
    ExportFormat format{};
    if (fmt->second == "jsonl")
        format = ExportFormat::jsonl;
    else if (fmt->second == "csv")
        format = ExportFormat::csv;
    else
        return std::unexpected("invalid format (expected jsonl or csv)");
    if (has("cursor") || has("limit"))
        return std::unexpected("cursor and limit are not accepted on the export");
    // The list parser's own `format` is the buffered json|csv selector; it never sees ours.
    software_list::Params rest = p;
    rest.erase("format");
    auto list = software_list::parse_list_params(rest);
    if (!list)
        return std::unexpected(list.error());
    list->base.query.limit = kPageRows;
    return ExportRequest{format, std::move(*list)};
}

/// One chunk for one page. JSONL: a line per row. CSV: the list writer's rows, with its header
/// line kept on the first chunk only (so there is exactly one writer of a CSV row).
[[nodiscard]] inline std::string format_chunk(const std::vector<SoftwareFleetRow>& rows,
                                              const software_list::DeviceFacts& facts,
                                              ExportFormat format, bool first_chunk) {
    if (format == ExportFormat::csv) {
        auto csv = software_list::list_csv(rows, facts);
        if (!first_chunk)
            csv.erase(0, software_list::kListCsvHeader.size() + 1); // header + '\n'
        return csv;
    }
    std::string out;
    for (const auto& r : rows) {
        out += software_catalogue::dump_safe(software_list::list_row_json(r, facts));
        out += '\n';
    }
    return out;
}

/// The export cap as the per-key cap of the ONE budget lease (see stream_budget.hpp,
/// `kSoftwareExportSurfaceKey`), clamped to the accepted range. The clamp is load-bearing, not
/// belt-and-braces: StreamBudget reads a per-key cap of 0 as "no per-key limit", so an unclamped 0
/// would turn the flag into "unlimited".
[[nodiscard]] constexpr std::size_t clamp_concurrency(int requested) noexcept {
    return static_cast<std::size_t>(std::clamp(requested, kMinConcurrency, kMaxConcurrency));
}

} // namespace yuzu::server::software_export
