/// @file software_export_routes.cpp
/// See software_export_routes.hpp.

#include "software_export_routes.hpp"

#include "model_param_helpers.hpp"
#include "principal_quota_gate.hpp"
#include "rest_a4_envelope_http.hpp"
#include "rest_audit.hpp"
#include "software_export_xlsx.hpp"
#include "software_list_model.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace swc = software_catalogue;
namespace swl = software_list;
namespace swe = software_export;

namespace {

constexpr const char* kVerb = "inventory.software.export";
constexpr const char* kTargetType = "Inventory";

// How a stream ended. The default is kAborted: the response's resource-releaser can run with
// nothing recorded when the client went away, the transport failed, or the server began shutting
// down mid-stream.
enum class Outcome { kAborted, kCompleted, kDegraded, kDeadline, kLimit };

// Indexes swe::kResults.
[[nodiscard]] std::string_view outcome_label(Outcome o) noexcept {
    static_assert(swe::kResults.size() == 5);
    switch (o) {
    case Outcome::kCompleted: return swe::kResults[0];
    case Outcome::kDegraded: return swe::kResults[1];
    case Outcome::kDeadline: return swe::kResults[2];
    case Outcome::kLimit: return swe::kResults[4];
    case Outcome::kAborted: break;
    }
    return swe::kResults[3];
}

struct Ctx {
    SoftwareExportRoutes::FleetReadFn fleet_read_fn;
    SoftwareExportRoutes::AuditFn audit_fn;
    SoftwareExportRoutes::RosterFn roster_fn;
    SoftwareExportRoutes::SecondsFn seconds_fn;
    SoftwareExportRoutes::Reads reads;
    yuzu::MetricsRegistry* metrics{nullptr};
    detail::StreamBudget* budget{nullptr}; ///< borrowed; the one held-open budget (ADR-0034)
    std::size_t concurrency{0};            ///< the export cap: the lease's per-key cap
    swe::Limits limits{};                  ///< the size limits, already clamped
    bool ready{false};
    // XLSX only (see software_export_routes.hpp). `xlsx_ready` is false when the temporary
    // directory is unusable: format=xlsx answers 503 and the other formats are unaffected.
    std::filesystem::path xlsx_tmp_dir;
    bool xlsx_ready{false};
    SoftwareExportRoutes::DiskFreeFn disk_free_fn; ///< bound at registration, never empty
    /// THE disk budget: one for the route, shared by every live XLSX export. Behind a pointer
    /// because it holds a mutex and a Ctx is moved into its shared_ptr.
    std::shared_ptr<swe::XlsxDiskBudget> disk_budget;

    [[nodiscard]] std::int64_t seconds() const {
        if (seconds_fn)
            return seconds_fn();
        return std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }
};

// The temporary workbook file and the disk grant of ONE XLSX export. A member of Stream, so both
// go back on every path that drops the Stream; the releaser and every refusal also call cleanup()
// directly so they are returned the moment the export ends, not when the last reference drops.
// `path` is set only once this export created the file itself, so a refused create (the name
// already existed) never removes somebody else's file.
struct XlsxFile {
    std::shared_ptr<swe::XlsxDiskBudget> budget;
    std::filesystem::path path;
    std::int64_t granted{0}; ///< sheet bytes granted by `budget` and not yet returned

    XlsxFile() = default;
    XlsxFile(const XlsxFile&) = delete;
    XlsxFile& operator=(const XlsxFile&) = delete;
    ~XlsxFile() { cleanup(); }

    void cleanup() noexcept {
        if (!path.empty()) {
            std::error_code ec;
            std::filesystem::remove(path, ec);
            path.clear();
        }
        if (granted > 0 && budget)
            budget->release(granted);
        granted = 0;
    }
};

// Everything one open stream carries. Owned by the provider and the releaser (both hold it), so it
// lives exactly as long as the response and the lease is freed with it at the latest.
struct Stream {
    std::shared_ptr<const Ctx> ctx;
    swe::ExportRequest request;
    authz::VisibleSet scope;
    detail::StreamBudget::Lease lease; ///< one worker of the one budget, held for the whole stream
    /// Where the next store read continues strictly after: the head, then the position each step
    /// reports. On a wide scope it names the last row SCANNED, which may be one the caller cannot
    /// see, so it lives only here: it is never formatted into a byte, header, log line, metric
    /// label or audit detail. Every store read is skip 0, so none uses an OFFSET.
    swc::DevicesOps::Anchor after{};
    std::unordered_map<std::string, std::string> hostnames;
    std::int64_t deadline{0};
    std::int64_t rows_written{0};  ///< data rows written so far (the CSV header is not a row)
    std::int64_t bytes_written{0}; ///< body bytes written so far
    bool first_chunk{true};
    Outcome outcome{Outcome::kAborted};
    std::string cid;
    XlsxFile xlsx; ///< XLSX only; empty for the streamed formats
};

void fail(httplib::Response& res, int status, std::string_view message,
          detail::A4ErrorOpts opts = {}) {
    res.status = status;
    // One place for the header, so every retryable 503 carries it (rounded up, like the v1 refusals).
    if (opts.retry_after_ms)
        res.set_header("Retry-After", std::to_string((*opts.retry_after_ms + 999) / 1000));
    res.set_content(detail::a4_error(res, message, opts), "application/json");
}

void bind_store_reads(SoftwareExportRoutes::Reads& r, SoftwareInventoryStore* s) {
    if (!s)
        return;
    if (!r.installs)
        r.installs = swc::devices_reader(*s);
    if (!r.last_seen)
        r.last_seen = [s](const std::vector<std::string>& ids) {
            return s->source_last_seen_bulk("installed_software", ids);
        };
    if (!r.distinct_versions)
        r.distinct_versions = [s](const std::string& name,
                                  const std::optional<std::vector<std::string>>& ids) {
            return s->installed_software_distinct_versions(name, ids);
        };
}

[[nodiscard]] bool reads_complete(const SoftwareExportRoutes::Reads& r) {
    return r.installs && r.last_seen && r.distinct_versions;
}

bool audit(const Ctx& c, const httplib::Request& req, const char* result,
           const std::string& target, const std::string& detail_text) {
    return detail::try_persist_audit(c.audit_fn, req, kVerb, result, kTargetType, target,
                                     detail_text);
}

void count_result(const Ctx& c, swe::ExportFormat format, Outcome o) {
    if (c.metrics)
        c.metrics
            ->counter("yuzu_server_software_export_total",
                      {{"format", std::string(swe::format_name(format))},
                       {"result", std::string(outcome_label(o))}})
            .increment();
}

// The per-page device facts: last polls from one bulk read, hostnames from the roster read once at
// the start of the stream. A blank hostname reads as unknown, like the list route. nullopt = the
// last-poll read degraded.
std::optional<swl::DeviceFacts> facts_for(const Stream& st, const std::vector<SoftwareFleetRow>& rows) {
    swl::DeviceFacts f;
    const auto ids = swl::page_agent_ids(rows);
    if (ids.empty())
        return f;
    auto seen = st.ctx->reads.last_seen(ids);
    if (!seen)
        return std::nullopt;
    f.last_seen = std::move(*seen);
    for (const auto& id : ids)
        if (const auto it = st.hostnames.find(id); it != st.hostnames.end() && !it->second.empty())
            f.hostname.emplace(id, it->second);
    return f;
}

// One page of the walk, as the two page consumers (the chunked pump and the XLSX build loop) see
// it. `last` is the ONLY end of the data.
struct Page {
    std::vector<SoftwareFleetRow> rows;
    swl::DeviceFacts facts;
    bool last{false};
};

// THE page walker: shutdown check, deadline, one scoped store read, the device facts, and the
// advance to the next position. nullopt ends the export and `st.outcome` says why: kDeadline,
// kDegraded, or kAborted (the server is closing).
std::optional<Page> read_step(Stream& st) {
    // Shutdown close-signal (StreamBudget::closing): a stream does not hold the server's stop for up
    // to the 900 s deadline. Counted as `aborted`, like a client that went away.
    if (st.ctx->budget->closing()) {
        spdlog::info("{}: server closing; aborting stream; cid={}", kVerb, st.cid);
        return std::nullopt;
    }
    if (st.ctx->seconds() >= st.deadline) {
        st.outcome = Outcome::kDeadline;
        spdlog::warn("{}: stream deadline reached; aborting; cid={}", kVerb, st.cid);
        return std::nullopt;
    }
    // No cursor is decoded on this path, so the only failure of a step is a degraded read.
    auto step = swc::read_scoped_step<swc::DevicesOps>(st.ctx->reads.installs,
                                                       st.request.list.base.query, st.after,
                                                       st.scope);
    if (!step) {
        st.outcome = Outcome::kDegraded;
        spdlog::warn("{}: installs read failed mid-stream; aborting; cid={}", kVerb, st.cid);
        return std::nullopt;
    }
    auto facts = facts_for(st, step->page.rows);
    if (!facts) {
        st.outcome = Outcome::kDegraded;
        spdlog::warn("{}: last-poll read failed mid-stream; aborting; cid={}", kVerb, st.cid);
        return std::nullopt;
    }
    Page page;
    page.rows = std::move(step->page.rows);
    page.facts = std::move(*facts);
    if (step->resume)
        st.after = std::move(*step->resume);
    else
        page.last = true;
    return page;
}

// One provider call: one store read, at most one chunk. Returning false aborts the transfer without
// its terminating chunk (the only failure signal available once headers are sent).
bool pump(Stream& st, httplib::DataSink& sink) {
    const auto page = read_step(st);
    if (!page)
        return false;
    // A wide scope can answer an EMPTY page that still has a position to resume from: nothing to
    // write, carry on. No sink.is_writable() check is needed here: httplib's chunked loop checks
    // the peer before every provider call, so a client that closed is noticed on the next turn.
    const auto chunk = swe::format_chunk(page->rows, page->facts, st.request.format, st.first_chunk);
    st.first_chunk = false;
    // The size limits are true maxima: a chunk that would pass either is not written, and the
    // transfer is cut like a deadline (no terminating chunk), so a file that ends cleanly is
    // always the whole answer.
    if (!swe::within_limits(st.ctx->limits, st.rows_written, st.bytes_written, page->rows.size(),
                            chunk.size())) {
        st.outcome = Outcome::kLimit;
        spdlog::warn("{}: size limit reached ({}/{} rows, {}/{} bytes written, next page +{} rows "
                     "+{} bytes); aborting; cid={}",
                     kVerb, st.rows_written, st.ctx->limits.max_rows, st.bytes_written,
                     st.ctx->limits.max_bytes, page->rows.size(), chunk.size(), st.cid);
        return false;
    }
    if (!chunk.empty() && !sink.write(chunk.data(), chunk.size()))
        return false; // client gone: outcome stays kAborted
    st.rows_written += static_cast<std::int64_t>(page->rows.size());
    st.bytes_written += static_cast<std::int64_t>(chunk.size());
    if (page->last) { // the ONLY end of the data
        st.outcome = Outcome::kCompleted;
        sink.done();
    }
    return true;
}

// Display-only: a roster that is unwired or cannot be read leaves the hostnames null.
void load_hostnames(Stream& st) {
    if (st.ctx->roster_fn)
        if (auto roster = st.ctx->roster_fn())
            for (auto& e : roster->rows)
                st.hostnames.emplace(std::move(e.agent_id), std::move(e.hostname));
}

// ── XLSX ────────────────────────────────────────────────────────────────────────────────────────

// The 23 header cells, split once from the list CSV's own header so the two formats cannot drift.
constexpr std::array<std::string_view, swl::kListCsvColumns> list_header() {
    std::array<std::string_view, swl::kListCsvColumns> out{};
    std::string_view rest = swl::kListCsvHeader;
    for (auto& cell : out) {
        const auto comma = rest.find(',');
        cell = rest.substr(0, comma);
        rest = comma == std::string_view::npos ? std::string_view{} : rest.substr(comma + 1);
    }
    return out;
}
constexpr auto kXlsxHeader = list_header();

// One disk grant always covers the largest possible row: every cell at the cell cap, every byte
// the worst escape, plus the row and the fixed parts.
static_assert(static_cast<std::int64_t>(swl::kListCsvColumns) *
                          (swe::kXlsxMaxCellBytes * swe::kXlsxMaxEscapeFactor +
                           swe::kXlsxCellOverheadBytes) +
                      swe::kXlsxRowOverheadBytes + swe::kXlsxSheetFixedBytes <=
                  swe::kXlsxDiskGrantBytes,
              "one XLSX disk grant must cover the largest possible row");

constexpr std::size_t kXlsxSliceBytes = std::size_t{64} << 10; // one provider call reads at most this

// The file name is built from the server's own correlation id restricted to [A-Za-z0-9_-]: no
// caller input reaches a path.
std::string safe_file_stem(std::string_view cid) {
    std::string out;
    for (const char c : cid)
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '_' || c == '-')
            out += c;
    return out.empty() ? std::string("x") : out;
}

// Asks the budget for the next step of sheet bytes. False = refused (the disk 503); the figures go
// to the log, because the caller sees only the remediation.
bool grant_more(Stream& st) {
    const Ctx& c = *st.ctx;
    const std::int64_t room = c.limits.max_bytes - st.xlsx.granted;
    if (room <= 0)
        return false; // callers check the limit first; never grant past it
    const std::int64_t ask = std::min(swe::kXlsxDiskGrantBytes, room);
    std::optional<std::uintmax_t> free_now;
    try {
        free_now = c.disk_free_fn();
    } catch (...) { // NOLINT(bugprone-empty-catch) - an unreadable figure refuses, below
    }
    if (c.disk_budget->grant(ask, free_now)) {
        st.xlsx.granted += ask;
        return true;
    }
    spdlog::error("{}: not enough free disk space for an xlsx export (free={} bytes, reserve={}, "
                  "asked={} sheet bytes, live exports hold={} sheet bytes, peak factor={}); cid={}",
                  kVerb, free_now ? std::to_string(*free_now) : std::string("unreadable"),
                  swe::kXlsxDiskReserveBytes, ask, c.disk_budget->granted(),
                  swe::kXlsxPeakDiskFactor, st.cid);
    return false;
}

enum class Built { kDone, kRowLimit, kByteLimit, kDegraded, kDeadline, kClosing, kDisk, kWriter };

// The build loop: the same page walk as the stream, written into the workbook. Nothing has been
// sent, so every outcome but kDone becomes an ordinary HTTP error.
Built build_xlsx(Stream& st, swe::XlsxSheetWriter& w, std::int64_t row_cap) {
    const auto max_bytes = st.ctx->limits.max_bytes;
    for (;;) {
        const auto page = read_step(st);
        if (!page) {
            switch (st.outcome) {
            case Outcome::kDeadline: return Built::kDeadline;
            case Outcome::kDegraded: return Built::kDegraded;
            default: return Built::kClosing;
            }
        }
        // A row past the limit is in the result, so the whole answer is over it.
        if (w.rows() + static_cast<std::int64_t>(page->rows.size()) > row_cap)
            return Built::kRowLimit;
        for (const auto& r : page->rows) {
            const auto cells = swl::list_row_cells(r, page->facts);
            bool asked = false;
            for (;;) {
                // The sheet-byte allowance is the lower of the limit and what the disk budget has
                // granted so far.
                const auto allowance = std::min(max_bytes, st.xlsx.granted);
                const auto result = w.append(cells, allowance);
                if (result == swe::XlsxSheetWriter::Append::ok)
                    break;
                if (result == swe::XlsxSheetWriter::Append::failed)
                    return Built::kWriter;
                if (allowance >= max_bytes)
                    return Built::kByteLimit;
                if (asked) // a fresh grant covers any row: reaching here is a logic error
                    return Built::kWriter;
                asked = true;
                if (!grant_more(st))
                    return Built::kDisk;
            }
        }
        if (page->last)
            return Built::kDone;
    }
}

// The XLSX arm, entered after the lease and the version-range step. The whole workbook is built
// into a temporary file BEFORE the response starts, then sent with a Content-Length.
void serve_xlsx(const std::shared_ptr<const Ctx>& ctx, const httplib::Request& req,
                httplib::Response& res, const std::string& cid, const std::string& target,
                swe::ExportRequest rq, const authz::VisibleSet& scope,
                detail::StreamBudget::Lease lease, std::int64_t deadline) {
    const std::string filters = swl::list_fingerprint(rq.list);
    auto st = std::make_shared<Stream>();
    st->ctx = ctx;
    st->scope = scope;
    st->deadline = deadline;
    st->cid = cid;
    st->lease = std::move(lease);
    st->xlsx.budget = ctx->disk_budget;
    st->request = std::move(rq);
    load_hostnames(*st);

    // Declared AFTER `st`, so on every exit it is destroyed FIRST: the library closes (and so
    // writes) the file in its destructor, and only then may the file be removed.
    std::optional<swe::XlsxSheetWriter> writer;

    // Every refusal: the writer closes, the file goes, the grant is returned, one failure audit row
    // names the outcome, the metric counts it, and the response is the standard envelope.
    const auto refuse = [&](Outcome o, int status, const std::string& message,
                            detail::A4ErrorOpts opts, std::string_view outcome_text) {
        const std::int64_t rows = writer ? writer->rows() : 0;
        writer.reset();
        st->xlsx.cleanup();
        (void)audit(*ctx, req, "failure", target,
                    "installs format=xlsx stream=false outcome=" + std::string(outcome_text) +
                        " rows=" + std::to_string(rows) + " filters=" + filters + "; cid=" + cid);
        count_result(*ctx, swe::ExportFormat::xlsx, o);
        fail(res, status, message, opts);
    };
    const auto refuse_writer = [&] {
        refuse(Outcome::kDegraded, 503, "xlsx export failed on the server",
               {.remediation = "retry the request, or use format=jsonl or csv"}, "writer");
    };

    const std::int64_t row_cap = std::min(ctx->limits.max_rows, swe::kXlsxMaxDataRows);
    constexpr std::string_view kNarrow = "narrow the filters, or use format=jsonl or csv";

    // The disk grant comes BEFORE the file exists, so a full volume costs nothing.
    if (!grant_more(*st)) {
        refuse(Outcome::kDegraded, 503, "not enough free disk space on the server for an xlsx export",
               {.remediation = "use format=jsonl or csv, or ask the administrator to free space on "
                               "the data volume"},
               "disk");
        return;
    }

    // The route creates the file itself, exclusively and owner-only; the library then opens it for
    // a truncating write. A create that fails overwrites nothing.
    const auto path = ctx->xlsx_tmp_dir / ("yuzu_export_" + safe_file_stem(cid) + ".xlsx");
    if (auto made = swe::create_owner_only_exclusive(path); !made) {
        spdlog::error("{}: {}; cid={}", kVerb, made.error(), cid);
        refuse_writer();
        return;
    }
    st->xlsx.path = path;
    if (auto opened = swe::XlsxSheetWriter::open(path, ctx->xlsx_tmp_dir, "Installed software",
                                                 kXlsxHeader);
        opened) {
        writer.emplace(std::move(*opened));
    } else {
        spdlog::error("{}: xlsx writer open failed: {}; cid={}", kVerb, opened.error(), cid);
        refuse_writer();
        return;
    }

    Built built = Built::kWriter;
    try {
        built = build_xlsx(*st, *writer, row_cap);
    } catch (...) {
        spdlog::error("{}: unexpected exception while building the xlsx workbook; cid={}", kVerb,
                      cid);
    }
    switch (built) {
    case Built::kDone: break;
    case Built::kRowLimit: {
        const bool own = row_cap == swe::kXlsxMaxDataRows;
        spdlog::warn("{}: xlsx row limit reached ({} rows written, limit {}); cid={}", kVerb,
                     writer->rows(), row_cap, cid);
        refuse(Outcome::kLimit, 413,
               "xlsx export is over the row limit of " + std::to_string(row_cap) + " rows (" +
                   (own ? "the sheet's own limit" : "--inventory-export-max-rows") + ")",
               {.remediation = kNarrow}, "limit_rows");
        return;
    }
    case Built::kByteLimit:
        spdlog::warn("{}: xlsx sheet limit reached ({} sheet bytes accounted, limit {}); cid={}",
                     kVerb, writer->sheet_bytes(), ctx->limits.max_bytes, cid);
        refuse(Outcome::kLimit, 413,
               "xlsx export is over --inventory-export-max-bytes (" +
                   std::to_string(ctx->limits.max_bytes) +
                   " bytes of uncompressed sheet, markup included)",
               {.remediation = kNarrow}, "limit_bytes");
        return;
    case Built::kDegraded:
        refuse(Outcome::kDegraded, 503, "software inventory store degraded - export read failed",
               {.retry_after_ms = swe::kRetryAfterMs, .remediation = "retry the request"},
               "degraded");
        return;
    case Built::kDeadline:
        refuse(Outcome::kDeadline, 503,
               "xlsx export did not finish within " + std::to_string(swe::kExportMaxSeconds) +
                   " seconds",
               {.remediation = kNarrow}, "deadline");
        return;
    case Built::kClosing:
        refuse(Outcome::kAborted, 503, "the server is shutting down",
               {.retry_after_ms = swe::kRetryAfterMs, .remediation = "retry shortly"}, "closing");
        return;
    case Built::kDisk:
        refuse(Outcome::kDegraded, 503, "not enough free disk space on the server for an xlsx export",
               {.remediation = "use format=jsonl or csv, or ask the administrator to free space on "
                               "the data volume"},
               "disk");
        return;
    case Built::kWriter:
        spdlog::error("{}: xlsx writer failed while building; cid={}", kVerb, cid);
        refuse_writer();
        return;
    }

    const std::int64_t rows = writer->rows();
    const std::int64_t truncated_cells = writer->cells_truncated();
    const auto closed = writer->close();
    if (!closed) {
        spdlog::error("{}: xlsx close failed: {}; cid={}", kVerb, closed.error(), cid);
        refuse_writer();
        return;
    }
    const std::uintmax_t size = *closed;
    // The last check: the finished file is never above the sheet it compresses, so this only
    // fires if the accounting were wrong; refusing is the safe answer to that.
    if (size > static_cast<std::uintmax_t>(ctx->limits.max_bytes)) {
        spdlog::error("{}: xlsx file ({} bytes) is over the byte limit ({}) although the sheet "
                      "accounting passed; cid={}",
                      kVerb, size, ctx->limits.max_bytes, cid);
        refuse(Outcome::kLimit, 413,
               "xlsx export is over --inventory-export-max-bytes (" +
                   std::to_string(ctx->limits.max_bytes) + " bytes)",
               {.remediation = kNarrow}, "limit_bytes");
        return;
    }
    // One deadline covers the build and the delivery: past it there is nothing left to deliver in.
    if (ctx->seconds() >= st->deadline) {
        spdlog::warn("{}: xlsx deadline reached after the build; cid={}", kVerb, cid);
        refuse(Outcome::kDeadline, 503,
               "xlsx export did not finish within " + std::to_string(swe::kExportMaxSeconds) +
                   " seconds",
               {.remediation = kNarrow}, "deadline");
        return;
    }
    auto in = std::make_shared<std::ifstream>(path, std::ios::binary);
    if (!*in) {
        spdlog::error("{}: cannot reopen the xlsx file for delivery; cid={}", kVerb, cid);
        refuse_writer();
        return;
    }

    // Audit BEFORE the provider, after the build: the row carries what was built. Set-and-proceed on
    // a miss (`Sec-Audit-Failed`, the file is still served), like the streamed formats.
    const bool audit_ok =
        audit(*ctx, req, "success", target,
              "installs format=xlsx stream=false rows=" + std::to_string(rows) +
                  " bytes=" + std::to_string(size) +
                  " truncated_cells=" + std::to_string(truncated_cells) + " filters=" + filters +
                  " cid=" + cid);
    if (!audit_ok)
        res.set_header("Sec-Audit-Failed", "true");
    res.set_header("Content-Disposition",
                   "attachment; filename=\"" +
                       std::string(swe::file_name(swe::ExportFormat::xlsx)) + "\"");
    res.set_header("X-Content-Type-Options", "nosniff");
    res.set_content_provider(
        static_cast<std::size_t>(size), std::string(swe::content_type(swe::ExportFormat::xlsx)),
        // Every call re-checks the two bounds the stream pump checks: the server closing and the
        // ONE deadline set at admission, so a slow reader cannot hold the worker, the lease, the
        // grant or the file past it. A false ends the transfer short of its Content-Length.
        [st, in](std::size_t offset, std::size_t length, httplib::DataSink& out) -> bool {
            try {
                if (st->ctx->budget->closing()) {
                    spdlog::info("{}: server closing; aborting xlsx delivery; cid={}", kVerb,
                                 st->cid);
                    return false; // outcome stays kAborted
                }
                if (st->ctx->seconds() >= st->deadline) {
                    st->outcome = Outcome::kDeadline;
                    spdlog::warn("{}: xlsx delivery deadline reached; aborting; cid={}", kVerb,
                                 st->cid);
                    return false;
                }
                const std::size_t want = std::min(length, kXlsxSliceBytes);
                std::string buf(want, '\0');
                in->clear();
                in->seekg(static_cast<std::streamoff>(offset));
                in->read(buf.data(), static_cast<std::streamsize>(want));
                if (static_cast<std::size_t>(in->gcount()) != want) {
                    st->outcome = Outcome::kDegraded;
                    spdlog::error("{}: xlsx file shorter than its size; aborting; cid={}", kVerb,
                                  st->cid);
                    return false;
                }
                return out.write(buf.data(), buf.size()); // false: client gone, outcome kAborted
            } catch (...) {
                st->outcome = Outcome::kDegraded;
                spdlog::error("{}: unexpected exception during xlsx delivery; aborting; cid={}",
                              kVerb, st->cid);
                return false;
            }
        },
        // Runs on every teardown path, from ~Response (an escaping exception is std::terminate).
        // The lease goes back FIRST, then the file and the grant (neither can throw); the counter
        // can, so it is last.
        detail::adopt_quota_slot_into_stream([st, in](bool success) noexcept {
            st->lease.release();
            try {
                in->close();
            } catch (...) { // NOLINT(bugprone-empty-catch) - nothing to do about a failed close
            }
            st->xlsx.cleanup();
            if (success)
                st->outcome = Outcome::kCompleted;
            try {
                count_result(*st->ctx, swe::ExportFormat::xlsx, st->outcome);
            } catch (...) { // NOLINT(bugprone-empty-catch) - a lost sample beats an abort
            }
        }));
}

// True when `dir` is a real directory this route may use: created owner-only if missing, a link or
// a file in its place is refused, and every regular file in it is removed (the directory belongs to
// this export alone, so this is the crash-recovery sweep: a process killed between create and
// remove leaves a file, and the next boot deletes it). Nothing is swept from a path that is not a
// real directory.
bool prepare_xlsx_dir(const std::filesystem::path& dir) {
    namespace fs = std::filesystem;
    if (dir.empty())
        return false;
    std::error_code ec;
    auto type = fs::symlink_status(dir, ec).type();
    if (ec && ec != std::errc::no_such_file_or_directory) {
        spdlog::error("{}: xlsx temporary directory unusable ({}): {}", kVerb, dir.string(),
                      ec.message());
        return false;
    }
    if (type == fs::file_type::not_found) {
        ec.clear();
        if (dir.has_parent_path())
            fs::create_directories(dir.parent_path(), ec);
        if (!ec)
            fs::create_directory(dir, ec);
        if (ec) {
            spdlog::error("{}: xlsx temporary directory cannot be created ({}): {}", kVerb,
                          dir.string(), ec.message());
            return false;
        }
        type = fs::file_type::directory;
    }
    if (type != fs::file_type::directory) {
        spdlog::error("{}: xlsx temporary directory is not a real directory ({}); xlsx export is "
                      "disabled",
                      kVerb, dir.string());
        return false;
    }
    fs::permissions(dir, fs::perms::owner_all, fs::perm_options::replace, ec);
    if (ec) {
        spdlog::error("{}: xlsx temporary directory permissions cannot be set ({}): {}", kVerb,
                      dir.string(), ec.message());
        return false;
    }
    std::size_t swept = 0;
    for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
        std::error_code entry_ec;
        if (fs::symlink_status(it->path(), entry_ec).type() == fs::file_type::regular &&
            fs::remove(it->path(), entry_ec))
            ++swept;
    }
    if (swept > 0)
        spdlog::warn("{}: removed {} leftover file(s) from the xlsx temporary directory", kVerb,
                     swept);
    return true;
}

} // namespace

void SoftwareExportRoutes::register_routes(HttpRouteSink& sink, Deps deps) {
    bind_store_reads(deps.reads, deps.store);
    Ctx built{.fleet_read_fn = std::move(deps.fleet_read_fn),
              .audit_fn = std::move(deps.audit_fn),
              .roster_fn = std::move(deps.roster_fn),
              .seconds_fn = std::move(deps.seconds_fn),
              .reads = std::move(deps.reads),
              .metrics = deps.metrics,
              .budget = deps.stream_budget,
              .concurrency = swe::clamp_concurrency(deps.concurrency),
              .limits = swe::clamp_limits(deps.limits)};
    built.ready = reads_complete(built.reads);
    built.xlsx_ready = prepare_xlsx_dir(deps.xlsx_tmp_dir);
    built.xlsx_tmp_dir = deps.xlsx_tmp_dir;
    built.disk_budget = std::make_shared<swe::XlsxDiskBudget>();
    built.disk_free_fn =
        deps.disk_free_fn
            ? std::move(deps.disk_free_fn)
            : SoftwareExportRoutes::DiskFreeFn([dir = deps.xlsx_tmp_dir]()
                                                   -> std::optional<std::uintmax_t> {
                  std::error_code ec;
                  const auto space = std::filesystem::space(dir, ec);
                  if (ec)
                      return std::nullopt;
                  return space.available;
              });
    const auto ctx = std::make_shared<const Ctx>(std::move(built));

    // GET /api/v1/inventory/software/export
    sink.Get("/api/v1/inventory/software/export", [ctx](const httplib::Request& req,
                                                       httplib::Response& res) {
        const auto cid = detail::make_correlation_id();
        res.set_header("X-Correlation-Id", cid); // echo on every path (A3)

        if (!ctx->fleet_read_fn) {
            spdlog::error("{}: fleet_read_fn unwired - misconfigured call site; failing closed; "
                          "cid={}",
                          kVerb, cid);
            fail(res, 503, "service unavailable");
            return;
        }
        // The SOLE authorization gate: renders 401/403/503 itself and returns !admitted. It runs
        // first, so a denied caller reaches no read and an unwired store is not visible to an
        // unauthenticated one.
        const auto gate = ctx->fleet_read_fn(req, res, "Inventory", "Read");
        if (!gate.admitted)
            return;
        if (!ctx->ready) {
            fail(res, 503, "software inventory store not available");
            return;
        }
        // Fail closed, never an unmetered export (the posture of the unwired fleet_read_fn above).
        // After the gate, so an unauthenticated caller cannot see the wiring.
        if (!ctx->budget) {
            spdlog::error("{}: stream_budget unwired - misconfigured call site; failing closed; "
                          "cid={}",
                          kVerb, cid);
            fail(res, 503, "service unavailable");
            return;
        }
        auto parsed = swe::parse_export_params(model_detail::to_params(req.params));
        if (!parsed) {
            fail(res, 400, parsed.error());
            return;
        }
        auto rq = std::move(*parsed);
        if (rq.format == swe::ExportFormat::xlsx && !ctx->xlsx_ready) {
            spdlog::error("{}: xlsx export requested but its temporary directory is unusable; "
                          "cid={}",
                          kVerb, cid);
            count_result(*ctx, swe::ExportFormat::xlsx, Outcome::kDegraded);
            fail(res, 503, "xlsx export is not configured on this server",
                 {.remediation = "use format=jsonl or csv"});
            return;
        }
        const std::string target = swl::audit_target(rq.list);

        // THE admission step (ADR-0034): one lease from the one budget, under the surface-wide key,
        // with the export cap as its per-key cap. Held by this frame until the stream takes it, so
        // every refusal below (a 400, a degraded version read) releases it on the way out.
        auto admitted = ctx->budget->try_acquire(detail::SseSurface::kSoftwareExport,
                                                 std::string(detail::kSoftwareExportSurfaceKey),
                                                 ctx->concurrency);
        if (!admitted.lease) {
            const bool export_cap =
                admitted.reject_reason != nullptr &&
                std::string_view(admitted.reject_reason) ==
                    detail::StreamBudget::kRejectPerPrincipal;
            const auto reason = export_cap ? swe::kRejectReasons[0] : swe::kRejectReasons[1];
            if (ctx->metrics)
                ctx->metrics
                    ->counter("yuzu_server_software_export_rejected_total",
                              {{"reason", std::string(reason)}})
                    .increment();
            (void)audit(*ctx, req, "denied", target,
                        std::string(export_cap ? "export concurrency limit reached"
                                               : "server held-open stream budget full") +
                            "; reason=" + std::string(reason) + "; cid=" + cid);
            fail(res, 503,
                 export_cap ? "too many concurrent software exports"
                            : "the server is running as many held-open requests as it is sized for",
                 {.retry_after_ms = swe::kRetryAfterMs,
                  .remediation = export_cap ? "retry when a running export has finished"
                                            : "retry shortly"});
            return;
        }

        // The ONE deadline of an XLSX export is set here, at admission, and covers the build and
        // the delivery together. (The streamed formats set theirs below, unchanged.)
        const std::int64_t xlsx_deadline =
            rq.format == swe::ExportFormat::xlsx ? ctx->seconds() + swe::kExportMaxSeconds : 0;

        if (rq.list.has_range()) {
            // Resolved once, against the caller's own scope, and held fixed for the whole stream.
            const auto distinct = ctx->reads.distinct_versions(
                rq.list.base.query.name, swl::scope_ids(gate.scope));
            if (!distinct) {
                (void)audit(*ctx, req, "failure", target,
                            "version read degraded; cid=" + cid);
                fail(res, 503, "software inventory store degraded - version range read failed",
                     {.retry_after_ms = swe::kRetryAfterMs, .remediation = "retry the request"});
                return;
            }
            auto set = swl::resolve_version_range(*distinct, *rq.list.range);
            if (!set) {
                fail(res, 400, set.error());
                return;
            }
            rq.list.base.query.versions = std::move(*set);
        }

        if (rq.format == swe::ExportFormat::xlsx) {
            serve_xlsx(ctx, req, res, cid, target, std::move(rq), gate.scope,
                       std::move(admitted.lease), xlsx_deadline);
            return;
        }

        // Audit BEFORE the provider: set_chunked_content_provider seals the headers. Set-and-proceed
        // on a miss (`Sec-Audit-Failed`, the file is still served): machine-scope inventory data,
        // the posture of the buffered export.
        const bool audit_ok = audit(*ctx, req, "success", target,
                                    "installs format=" + std::string(swe::format_name(rq.format)) +
                                        " stream=true filters=" + swl::list_fingerprint(rq.list) +
                                        " cid=" + cid);
        if (!audit_ok)
            res.set_header("Sec-Audit-Failed", "true");

        auto st = std::make_shared<Stream>();
        st->ctx = ctx;
        st->scope = gate.scope;
        st->deadline = ctx->seconds() + swe::kExportMaxSeconds;
        st->cid = cid;
        load_hostnames(*st);

        res.set_header("Content-Disposition",
                       "attachment; filename=\"" + std::string(swe::file_name(rq.format)) + "\"");
        res.set_header("X-Content-Type-Options", "nosniff");
        const std::string content_type(swe::content_type(rq.format));
        st->request = std::move(rq);
        st->lease = std::move(admitted.lease);
        res.set_chunked_content_provider(
            content_type,
            [st](size_t, httplib::DataSink& out) {
                try {
                    return pump(*st, out);
                } catch (...) {
                    st->outcome = Outcome::kDegraded;
                    spdlog::error("{}: unexpected exception mid-stream; aborting; cid={}", kVerb,
                                  st->cid);
                    return false;
                }
            },
            // Runs on every teardown path (clean end, abort, dropped client, deadline, shutdown),
            // from ~Response, where an escaping exception is std::terminate. The lease goes back
            // FIRST: it is the one step that must not be skipped (release is noexcept), and the
            // counter below can throw. The same releaser then frees an adopted engine quota slot
            // (UP-1) after this body, so the principal's concurrency reservation lasts as long as
            // the stream, not as long as the request.
            detail::adopt_quota_slot_into_stream([st](bool) noexcept {
                st->lease.release();
                try {
                    count_result(*st->ctx, st->request.format, st->outcome);
                } catch (...) { // NOLINT(bugprone-empty-catch) - a lost sample beats an abort
                }
            }));
    });
}

} // namespace yuzu::server
