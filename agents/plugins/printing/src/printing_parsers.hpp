// printing_parsers.hpp — PURE row types, IPP -> row mappers, winspool
// bit -> row mappers, and pipe-delimited output formatting for the
// `printing` plugin. No OS headers, no I/O — every symbol here is usable by
// the unit tests on every host, per printing_ipp.hpp's own posture.
//
// DOCUMENT-TITLE POSTURE (decided): `jobs` ships `document` (the job's
// name/title) because it is the identifier an operator needs to read in
// order to pick which job a subsequent `clear_queue` call should target —
// there is no other operator-facing way to distinguish two jobs from the
// same owner on the same printer. This is user content (an end user's
// document name reaches the operator's screen), so it carries the same
// posture as any other instruction-result field: retained only as part of
// the server's ordinary instruction-result history, never forwarded to
// daily-sync, TAR, or DEX. Retaining COMPLETED job history beyond a single
// `jobs` call is explicitly deferred (D4) — this plugin has no history
// store of its own.
#pragma once

#include "printing_ipp.hpp"

#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <ctime>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::printing {

struct PrinterRow {
    std::string name;
    std::string state;         // idle | processing | stopped | unknown
    std::string state_reasons; // comma-joined values, or "-"
    bool is_default = false;
    std::string make_model;
    std::string uri;
    int64_t queued_jobs = -1; // -1 = unknown
};

struct JobRow {
    std::string printer;
    int64_t job_id = 0;
    std::string owner;
    std::string document; // see file banner — DOCUMENT-TITLE POSTURE
    std::string status;   // pending|held|processing|stopped|canceled|aborted|completed|unknown
    std::string submitted_at; // ISO-8601 UTC, or "-"
    int64_t size_bytes = -1;  // -1 = unknown
};

namespace detail {

[[nodiscard]] inline const ipp::Attr* find_attr(const std::vector<ipp::Attr>& attrs,
                                                  std::string_view name) {
    for (const auto& a : attrs) {
        if (a.name == name)
            return &a;
    }
    return nullptr;
}

[[nodiscard]] inline std::string first_value(const ipp::Attr* a, std::string_view fallback = {}) {
    if (a != nullptr && !a->values.empty())
        return a->values.front();
    return std::string(fallback);
}

// RFC 8010 §3.5.2: the `integer`/`enum` value tags carry a 4-byte, two's
// complement, BIG-ENDIAN binary integer — never decimal ASCII text. The
// wire bytes land in `Attr::values` as a `std::string` purely as a byte
// container (decode()/encode_request() never interpret its content), so
// this reads it back as the 4 raw bytes it is.
[[nodiscard]] inline std::optional<int64_t> first_int(const ipp::Attr* a) {
    if (a == nullptr || a->values.empty())
        return std::nullopt;
    const std::string& s = a->values.front();
    if (s.size() != 4)
        return std::nullopt;
    const int32_t v = (static_cast<int32_t>(static_cast<uint8_t>(s[0])) << 24) |
                       (static_cast<int32_t>(static_cast<uint8_t>(s[1])) << 16) |
                       (static_cast<int32_t>(static_cast<uint8_t>(s[2])) << 8) |
                       static_cast<int32_t>(static_cast<uint8_t>(s[3]));
    return static_cast<int64_t>(v);
}

[[nodiscard]] inline std::string printer_state_from_ipp_enum(std::optional<int64_t> state) {
    if (!state)
        return "unknown";
    switch (*state) {
    case 3:
        return "idle";
    case 4:
        return "processing";
    case 5:
        return "stopped";
    default:
        return "unknown";
    }
}

[[nodiscard]] inline std::string job_state_from_ipp_enum(std::optional<int64_t> state) {
    if (!state)
        return "unknown";
    switch (*state) {
    case 3:
        return "pending";
    case 4:
        return "held";
    case 5:
        return "processing";
    case 6:
        return "stopped";
    case 7:
        return "canceled";
    case 8:
        return "aborted";
    case 9:
        return "completed";
    default:
        return "unknown";
    }
}

/// RFC 2911 §4.1.14 `dateTime` — 11 raw octets: year (uint16 BE), month,
/// day, hour, minute, second, deci-second, direction-from-UTC ('+'/'-'),
/// hours-from-UTC, minutes-from-UTC. This is the wire value IPP attributes
/// like `date-time-at-creation` carry, distinct from `time-at-creation`
/// (a plain `integer` relative to the printer's own `printer-up-time`, NOT
/// Unix epoch — using it as epoch seconds silently produces a bogus
/// near-1970 timestamp on any implementation whose uptime counter is not
/// coincidentally close to the real epoch). Converts to the real UTC
/// instant by undoing the printer's reported UTC offset, never assuming
/// the printer's local clock is itself UTC.
[[nodiscard]] inline std::string iso8601_from_ipp_datetime(std::string_view raw) {
    if (raw.size() != 11)
        return "-";
    const auto b = [&](std::size_t i) { return static_cast<unsigned char>(raw[i]); };
    const int year = (b(0) << 8) | b(1);
    const int month = b(2), day = b(3), hour = b(4), minute = b(5), second = b(6);
    const char direction = raw[8];
    const int off_hours = b(9), off_minutes = b(10);
    if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 60 ||
        (direction != '+' && direction != '-'))
        return "-";

    std::tm tm{};
    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min = minute;
    tm.tm_sec = second;
    // Interpret tm as a UTC-naive wall clock (the printer's local time at
    // its reported offset) without consulting any local timezone database.
#if defined(_WIN32)
    const std::time_t naive = _mkgmtime(&tm);
#else
    const std::time_t naive = timegm(&tm);
#endif
    if (naive == static_cast<std::time_t>(-1))
        return "-";
    const int off_seconds = (off_hours * 3600) + (off_minutes * 60);
    const std::time_t utc = (direction == '-') ? (naive + off_seconds) : (naive - off_seconds);

    std::tm out_tm{};
#if defined(_WIN32)
    if (gmtime_s(&out_tm, &utc) != 0)
        return "-";
#else
    if (gmtime_r(&utc, &out_tm) == nullptr)
        return "-";
#endif
    char buf[32];
    const std::size_t n = std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &out_tm);
    if (n == 0)
        return "-";
    return std::string(buf, n);
}

} // namespace detail

/// Maps every printer-attributes group (0x04) in a CUPS-Get-Printers
/// response into a `PrinterRow`. `default_name`, when non-empty, marks the
/// one row whose `printer-name` matches it as `is_default` — the plugin
/// resolves that name from a separate CUPS-Get-Default call.
[[nodiscard]] inline std::vector<PrinterRow>
printers_from_ipp(const ipp::Message& msg, std::string_view default_name = {}) {
    std::vector<PrinterRow> out;
    for (const auto& [group_tag, attrs] : msg.groups) {
        if (group_tag != ipp::kTagPrinterAttributes)
            continue;
        const std::string name = detail::first_value(detail::find_attr(attrs, "printer-name"));
        if (name.empty())
            continue; // defensive: a real CUPS response always sends this

        PrinterRow row;
        row.name = name;
        row.state =
            detail::printer_state_from_ipp_enum(detail::first_int(detail::find_attr(attrs, "printer-state")));
        if (const auto* reasons = detail::find_attr(attrs, "printer-state-reasons");
            reasons != nullptr && !reasons->values.empty()) {
            std::string joined;
            for (std::size_t i = 0; i < reasons->values.size(); ++i) {
                if (i != 0)
                    joined += ",";
                joined += reasons->values[i];
            }
            row.state_reasons = joined;
        } else {
            row.state_reasons = "-";
        }
        row.make_model = detail::first_value(detail::find_attr(attrs, "printer-make-and-model"), "-");
        row.uri = detail::first_value(detail::find_attr(attrs, "printer-uri-supported"), "-");
        row.queued_jobs = detail::first_int(detail::find_attr(attrs, "queued-job-count")).value_or(-1);
        row.is_default = !default_name.empty() && row.name == default_name;
        out.push_back(std::move(row));
    }
    return out;
}

/// Maps every job-attributes group (0x02) in a Get-Jobs response into a
/// `JobRow`. A group with no parseable `job-id` is skipped defensively
/// (never fabricated as job 0).
[[nodiscard]] inline std::vector<JobRow> jobs_from_ipp(const ipp::Message& msg) {
    std::vector<JobRow> out;
    for (const auto& [group_tag, attrs] : msg.groups) {
        if (group_tag != ipp::kTagJobAttributes)
            continue;
        const auto id = detail::first_int(detail::find_attr(attrs, "job-id"));
        if (!id)
            continue;

        JobRow row;
        row.job_id = *id;
        row.printer = detail::first_value(detail::find_attr(attrs, "job-printer-uri"), "-");
        row.owner = detail::first_value(detail::find_attr(attrs, "job-originating-user-name"), "-");
        row.document = detail::first_value(detail::find_attr(attrs, "job-name"), "-");
        row.status =
            detail::job_state_from_ipp_enum(detail::first_int(detail::find_attr(attrs, "job-state")));
        row.submitted_at =
            detail::iso8601_from_ipp_datetime(detail::first_value(detail::find_attr(attrs, "date-time-at-creation")));
        const auto k_octets = detail::first_int(detail::find_attr(attrs, "job-k-octets"));
        row.size_bytes = k_octets ? (*k_octets * 1024) : -1;
        out.push_back(std::move(row));
    }
    return out;
}

// ── winspool bit -> row mappers ─────────────────────────────────────────────
//
// Reproduced <winspool.h> bit values here (not #included) so this header
// stays platform-pure and its mapper functions are usable by the unit tests
// on every host. `kPrinterStatusPaused` (0x1) is REAL CAPTURE the-rig —
// P93-2/P93-3 observed it live on `Microsoft Print to PDF` under both admin
// and SYSTEM (tests/unit/fixtures/wave9/printing/windows/enum_printers.txt).
// The remaining bits were never exercised by that printer (no error/
// offline/not-available printer, no non-pending job state, was available to
// probe) and stay RECONSTRUCTION against the documented PRINTER_STATUS_*/
// JOB_STATUS_* bit meanings.
namespace winspool_bits {

inline constexpr uint32_t kPrinterStatusPaused = 0x00000001;
inline constexpr uint32_t kPrinterStatusError = 0x00000002;
inline constexpr uint32_t kPrinterStatusOffline = 0x00000080;
inline constexpr uint32_t kPrinterStatusNotAvailable = 0x00001000;

inline constexpr uint32_t kJobStatusPaused = 0x00000001;
inline constexpr uint32_t kJobStatusError = 0x00000002;
inline constexpr uint32_t kJobStatusSpooling = 0x00000008;
inline constexpr uint32_t kJobStatusPrinting = 0x00000010;
inline constexpr uint32_t kJobStatusOffline = 0x00000020;
inline constexpr uint32_t kJobStatusPaperout = 0x00000040;
inline constexpr uint32_t kJobStatusPrinted = 0x00000080;
inline constexpr uint32_t kJobStatusDeleted = 0x00000100;
inline constexpr uint32_t kJobStatusBlockedDevq = 0x00000200;
inline constexpr uint32_t kJobStatusUserIntervention = 0x00000400;
inline constexpr uint32_t kJobStatusRestart = 0x00000800;

} // namespace winspool_bits

/// PRINTER_INFO_2's `Status`/`cJobs` -> the same idle/processing/stopped/
/// unknown vocabulary the IPP leg reports (never a fourth Windows-only
/// state) — an error/offline/not-available/paused printer reports
/// "stopped", a printer with queued jobs and no such flag reports
/// "processing", otherwise "idle".
[[nodiscard]] inline std::string printer_state_from_winspool(uint32_t status, uint32_t c_jobs) {
    using namespace winspool_bits;
    if ((status & (kPrinterStatusError | kPrinterStatusOffline | kPrinterStatusNotAvailable |
                   kPrinterStatusPaused)) != 0)
        return "stopped";
    if (c_jobs > 0)
        return "processing";
    return "idle";
}

/// JOB_INFO_2's `Status` -> the same pending/held/processing/stopped/
/// canceled/aborted/completed/unknown vocabulary the IPP leg reports.
[[nodiscard]] inline std::string job_status_from_winspool(uint32_t status) {
    using namespace winspool_bits;
    if ((status & kJobStatusDeleted) != 0)
        return "canceled";
    if ((status & kJobStatusError) != 0)
        return "aborted";
    if ((status & kJobStatusPrinted) != 0)
        return "completed";
    if ((status & kJobStatusPrinting) != 0)
        return "processing";
    if ((status & (kJobStatusPaused | kJobStatusUserIntervention | kJobStatusPaperout |
                   kJobStatusBlockedDevq | kJobStatusOffline | kJobStatusRestart)) != 0)
        return "held";
    if ((status & kJobStatusSpooling) != 0 || status == 0)
        return "pending";
    return "unknown";
}

// ── output formatting ───────────────────────────────────────────────────────

[[nodiscard]] inline std::string format_printer_row(const PrinterRow& r) {
    return std::format("printer|{}|{}|{}|{}|{}|{}|{}", yuzu::util::safe_output_field(r.name), r.state,
                        yuzu::util::safe_output_field(r.state_reasons), r.is_default ? 1 : 0,
                        yuzu::util::safe_output_field(r.make_model), yuzu::util::safe_output_field(r.uri),
                        r.queued_jobs);
}

[[nodiscard]] inline std::string format_job_row(const JobRow& r) {
    return std::format("job|{}|{}|{}|{}|{}|{}|{}", yuzu::util::safe_output_field(r.printer), r.job_id,
                        yuzu::util::safe_output_field(r.owner), yuzu::util::safe_output_field(r.document),
                        r.status, r.submitted_at, r.size_bytes);
}

/// `outcome`: canceled | not_found | refused | error. An empty `printer`
/// (the `missing_printer` row) is emitted as "-", matching the definition's
/// documented "-" when the param itself was missing.
[[nodiscard]] inline std::string format_clear_queue_row(std::string_view printer, int64_t job_id,
                                                          std::string_view outcome,
                                                          std::string_view detail) {
    return std::format("clear_queue|{}|{}|{}|{}", printer.empty() ? "-" : yuzu::util::safe_output_field(printer),
                        job_id, outcome, yuzu::util::safe_output_field(detail));
}

/// How a CUPS response status (Cancel-Job, or the pre-cancel Get-Jobs) maps onto a
/// `clear_queue` outcome; `canceled` means the operation succeeded (successful-*).
enum class CancelStatusClass { canceled, not_found, refused, error };

/// Pure so the mapping is unit-testable without a cupsd. Status values are
/// RFC 8011 §4.1.6 (client-error-*) and RFC 8010 §3.1.6.1 (successful-*):
///   0x0000-0x00FF successful-*            -> canceled
///   0x0406 client-error-not-found         -> not_found
///   0x0401 client-error-forbidden         -> refused
///   0x0402 client-error-not-authenticated -> refused
///   0x0403 client-error-not-authorized    -> refused
/// Everything else, deliberately including 0x0400 client-error-bad-request
/// (a malformed request is a protocol fault, not an authorization decision),
/// is `error` so it surfaces as `unexpected_status` rather than a false
/// "refused".
[[nodiscard]] inline CancelStatusClass classify_cancel_job_status(uint16_t status) noexcept {
    if (status <= 0x00FF)
        return CancelStatusClass::canceled;
    switch (status) {
    case 0x0406:
        return CancelStatusClass::not_found;
    case 0x0401:
    case 0x0402:
    case 0x0403:
        return CancelStatusClass::refused;
    default:
        return CancelStatusClass::error;
    }
}

/// How a failed Windows `OpenPrinterW` maps onto a `clear_queue` outcome.
enum class OpenPrinterFailure { not_found, refused, error };

/// `last_error` is `GetLastError()` read immediately after the failed call.
/// Win32 values are stable ABI, restated here (winerror.h) so the mapping
/// stays in the pure header: 5 ERROR_ACCESS_DENIED -> refused (the printer
/// exists but the caller may not open its queue), 1801
/// ERROR_INVALID_PRINTER_NAME -> not_found. Every other failure (spooler
/// stopped, RPC unavailable, ...) is `error`: reporting it as not_found would
/// tell an operator a printer is gone when the spooler is merely down.
[[nodiscard]] inline OpenPrinterFailure classify_open_printer_error(uint32_t last_error) noexcept {
    constexpr uint32_t kErrorAccessDenied = 5;
    constexpr uint32_t kErrorInvalidPrinterName = 1801;
    if (last_error == kErrorAccessDenied)
        return OpenPrinterFailure::refused;
    if (last_error == kErrorInvalidPrinterName)
        return OpenPrinterFailure::not_found;
    return OpenPrinterFailure::error;
}

/// True only for a plain local printer name: none of `\`, `/` or `:`. Those
/// characters can make OpenPrinterW reach a remote server (`\\server\queue`,
/// the `//server/queue` form `safe_output_field` renders it as in the
/// `printers`/`jobs` rows, `http://host/printers/x/.printer`, ...), and
/// OpenPrinterW returns the SAME 1801 for an unreachable server as for a missing
/// local printer, so a not-found is definitive only for a plain name.
/// Conservative by construction: only a name free of all three characters may
/// claim a definitive not-found; enumerating remote-capable shapes is open-ended.
[[nodiscard]] inline bool printer_name_is_plain_local(std::string_view name) noexcept {
    return name.find_first_of("\\/:") == std::string_view::npos;
}

// ───────────────────────── clear_queue on macOS/Linux: job-to-printer binding ──
//
// cupsd's Cancel-Job looks a job up by id alone: with a non-zero job-id the
// printer-uri is neither validated nor compared to the job's queue
// (scheduler/ipp.c cancel_job()). So the named printer only constrains the
// cancel if the agent checks it first. Everything below is pure so the whole
// ladder is unit-testable with an injected transport.

/// One IPP round trip's outcome, as the plugin's transport layer reports it.
struct IppResult {
    bool transport_ok = false;
    long http_status = 0;
    std::optional<ipp::Message> message;
};

/// IPP name(127): the longest printer name cupsd accepts. A longer value is
/// refused before any request is built.
inline constexpr std::size_t kMaxPosixPrinterNameBytes = 127;

/// RFC 3986 path-segment encoding: every byte outside the unreserved set
/// (A-Z a-z 0-9 - . _ ~) becomes %XX. The printer name goes into the request
/// URI, which cupsd percent-DECODES: a raw `%00` truncated the resource at the
/// NUL and turned the printer-uri into the all-printers collection, so the
/// binding check passed for any job id. Encoding makes `%` a literal `%25`.
[[nodiscard]] inline std::string percent_encode_path_segment(std::string_view s) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size());
    for (const char ch : s) {
        const auto c = static_cast<unsigned char>(ch);
        const bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                                (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~';
        if (unreserved) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 0x0F]);
        }
    }
    return out;
}

/// Decodes %XX sequences; a `%` not followed by two hex digits stays literal.
[[nodiscard]] inline std::string percent_decode(std::string_view s) {
    const auto hex = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            const int hi = hex(s[i + 1]);
            const int lo = hex(s[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        out.push_back(s[i]);
    }
    return out;
}

/// The printer NAME from what an operator supplied. The `jobs` action prints a
/// printer as a destination URI on macOS/Linux (`ipp://localhost:631/printers/Q`,
/// or `/classes/C` for a class), so that form is accepted and reduced to its
/// last path segment (percent-decoded). Anything else is returned unchanged. A
/// segment holding `/` or `#` is not a name (cupsd bars both in a queue name) and is
/// returned unchanged; a `?` IS part of a name (cupsd allows it), so the `jobs` URI of
/// a queue named with one is accepted.
[[nodiscard]] inline std::string printer_name_from_operand(std::string_view operand) {
    for (const std::string_view scheme : {std::string_view{"ipp://"}, std::string_view{"ipps://"}}) {
        if (!operand.starts_with(scheme))
            continue;
        const auto rest = operand.substr(scheme.size());
        const auto slash = rest.find('/');
        if (slash == std::string_view::npos)
            break;
        const auto path = rest.substr(slash);
        for (const std::string_view prefix : {std::string_view{"/printers/"}, std::string_view{"/classes/"}}) {
            if (!path.starts_with(prefix))
                continue;
            const auto segment = path.substr(prefix.size());
            if (segment.find_first_of("/#") != std::string_view::npos)
                return std::string(operand);
            return percent_decode(segment);
        }
        break;
    }
    return std::string(operand);
}

/// Strict UTF-8 (RFC 3629): no overlong forms, no surrogates, nothing above
/// U+10FFFF. A row is a protobuf string, which the server must parse: a stray
/// byte such as the 0xFF a pasted `%FF` decodes to would make the whole
/// CommandResponse unparseable and end the server's read loop.
[[nodiscard]] inline bool is_valid_utf8(std::string_view s) noexcept {
    std::size_t i = 0;
    const auto at = [&](std::size_t k) { return static_cast<unsigned char>(s[k]); };
    const auto cont = [&](std::size_t k) { return k < s.size() && (at(k) & 0xC0) == 0x80; };
    while (i < s.size()) {
        const unsigned c = at(i);
        if (c < 0x80) {
            i += 1;
        } else if (c >= 0xC2 && c <= 0xDF) {
            if (!cont(i + 1)) return false;
            i += 2;
        } else if (c >= 0xE0 && c <= 0xEF) {
            if (!cont(i + 1) || !cont(i + 2)) return false;
            const unsigned c1 = at(i + 1);
            if (c == 0xE0 && c1 < 0xA0) return false; // overlong
            if (c == 0xED && c1 > 0x9F) return false; // surrogate
            i += 3;
        } else if (c >= 0xF0 && c <= 0xF4) {
            if (!cont(i + 1) || !cont(i + 2) || !cont(i + 3)) return false;
            const unsigned c1 = at(i + 1);
            if (c == 0xF0 && c1 < 0x90) return false; // overlong
            if (c == 0xF4 && c1 > 0x8F) return false; // above U+10FFFF
            i += 4;
        } else {
            return false; // 0x80-0xC1 (stray/overlong lead) and 0xF5-0xFF
        }
    }
    return true;
}

/// A name the macOS/Linux path will build a request for: non-empty, within the
/// IPP name limit, valid UTF-8, and free of control characters (including one
/// that appears only after percent-decoding a pasted URI, e.g. `%00`).
[[nodiscard]] inline bool printer_name_is_valid_posix(std::string_view name) noexcept {
    if (name.empty() || name.size() > kMaxPosixPrinterNameBytes || !is_valid_utf8(name))
        return false;
    return std::none_of(name.begin(), name.end(), [](char c) {
        const auto u = static_cast<unsigned char>(c);
        return u < 0x20 || u == 0x7F;
    });
}

/// `ipp://localhost/printers/<encoded name>`
[[nodiscard]] inline std::string printer_uri_for(std::string_view name) {
    return "ipp://localhost/printers/" + percent_encode_path_segment(name);
}

/// Operation attributes of the Get-Jobs that lists ONE printer's not-completed
/// jobs (pending/held/processing/stopped), asking only for each job's id and its
/// printer URI. A nonexistent printer makes cupsd answer not-found.
[[nodiscard]] inline std::vector<ipp::OperationAttr> job_binding_check_attrs(std::string_view printer_name) {
    std::vector<ipp::OperationAttr> attrs;
    attrs.push_back({ipp::kTagUri, "printer-uri", printer_uri_for(printer_name), {}});
    attrs.push_back({ipp::kTagKeyword, "which-jobs", "not-completed", {}});
    attrs.push_back({ipp::kTagKeyword, "requested-attributes", "job-id", {"job-printer-uri"}});
    return attrs;
}

/// The printer NAME out of a `job-printer-uri` that cupsd itself generated
/// (`ipp[s]://host[:port]/printers/NAME` or `/classes/NAME`): the WHOLE remainder,
/// percent-decoded. Unlike printer_name_from_operand (which refuses a segment
/// holding `/` or `#` because an operator typed it), this reads the whole remainder
/// and never rejects a queue name: libcups's httpAssembleURIf, which cupsd's
/// copy_job_attrs() uses to build the URI, leaves a `?` in a name unencoded (measured
/// with a scratch driver), and a queue named with one is legal. Anything that is not
/// that shape yields "", which never equals a printer name.
[[nodiscard]] inline std::string printer_name_from_cupsd_uri(std::string_view uri) {
    for (const std::string_view scheme : {std::string_view{"ipp://"}, std::string_view{"ipps://"}}) {
        if (!uri.starts_with(scheme))
            continue;
        const auto rest = uri.substr(scheme.size());
        const auto slash = rest.find('/');
        if (slash == std::string_view::npos)
            return {};
        const auto path = rest.substr(slash);
        for (const std::string_view prefix : {std::string_view{"/printers/"}, std::string_view{"/classes/"}}) {
            if (path.starts_with(prefix))
                return percent_decode(path.substr(prefix.size()));
        }
        return {};
    }
    return {};
}

/// ASCII case-insensitive equality. CUPS resolves printer names case-insensitively
/// (cupsd answers a Get-Jobs for `YUZU4616A` with the jobs of `yuzu4616a`, whose
/// job-printer-uri is lower case), so an exact comparison would report a live job
/// as not found.
[[nodiscard]] inline bool ascii_iequals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size())
        return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        const auto fold = [](char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; };
        if (fold(a[i]) != fold(b[i]))
            return false;
    }
    return true;
}

/// What a printer's not-completed listing says about one job id.
enum class JobListing {
    absent,      // the id is not listed at all
    elsewhere,   // listed, but its own job-printer-uri names a DIFFERENT printer, or is not a
                 // recognised ipp[s]://.../printers|classes/NAME URI (fail closed either way)
    unconfirmed, // listed, but with no (or an empty) job-printer-uri to confirm the printer:
                 // a defensive verdict for a server that omits the attribute -- upstream
                 // copy_job_attrs() emits it whenever it is requested, even under
                 // JobPrivateValues (read in the upstream source), and this Mac's cupsd
                 // returns it when asked (real capture)
    on_printer,  // listed AND its own job-printer-uri names the requested printer
};

/// The second guard behind the encoded printer-uri: whatever cupsd made of the
/// request URI, a job is accepted only when its OWN job-printer-uri names the
/// requested printer (compared case-insensitively). "-" is jobs_from_ipp's
/// placeholder for an absent attribute.
[[nodiscard]] inline JobListing classify_job_listing(const std::vector<JobRow>& rows, int64_t job_id,
                                                      std::string_view printer_name) {
    bool seen = false;
    bool unconfirmed = false;
    for (const auto& r : rows) {
        if (r.job_id != job_id)
            continue;
        seen = true;
        if (r.printer == "-" || r.printer.empty()) { // absent, or present but empty
            unconfirmed = true;
            continue;
        }
        if (ascii_iequals(printer_name_from_cupsd_uri(r.printer), printer_name))
            return JobListing::on_printer;
    }
    if (!seen)
        return JobListing::absent;
    return unconfirmed ? JobListing::unconfirmed : JobListing::elsewhere;
}

/// The printer as a row shows it on the macOS/Linux path: the printer NAME (a pasted
/// destination URI is reduced to its name, so a long host never bloats the row), or
/// "-" when the value is not a name the agent will use.
[[nodiscard]] inline std::string printer_echo_posix(std::string_view operand) {
    const std::string name = printer_name_from_operand(operand);
    return printer_name_is_valid_posix(name) ? name : std::string("-");
}

/// Windows: a name the agent will hand to OpenPrinterW. A comma (or a control
/// character, or invalid UTF-8) is refused: OpenPrinterW gives `,` special meaning
/// (address syntaxes such as `,XcvPort ...`, `Printer, Job N`, `,LocalPrintServer`),
/// and Windows printer names cannot contain one, so such a name is never a real
/// printer. (Measured on real Windows with the agent's PRINTER_ACCESS_USE only
/// `,XcvMonitor Local Port` was recognised, with error 5; the refusal is hardening.)
[[nodiscard]] inline bool printer_name_is_valid_windows(std::string_view name) noexcept {
    if (name.empty() || !is_valid_utf8(name))
        return false;
    return std::none_of(name.begin(), name.end(), [](char c) {
        const auto u = static_cast<unsigned char>(c);
        return c == ',' || u < 0x20 || u == 0x7F;
    });
}

enum class ClearQueueStatus { ok, unavailable, permission_denied };

/// What `clear_queue` reports: the shell applies it to the command context.
struct ClearQueueDisposition {
    int rc = 1;
    ClearQueueStatus status = ClearQueueStatus::unavailable;
    bool full = false; // completeness FULL (true) or PARTIAL (false)
    std::string detail;
    std::string row;
};

/// The per-OS failure tokens the shell owns (`<os>:cups:<detail>`).
struct ClearQueueTokens {
    std::string_view connect_failed;
    std::string_view decode_failed;
    std::string_view access_denied;
    std::string_view not_found;
    std::string_view unexpected_status;
};

/// The whole macOS/Linux cancel ladder over an injected transport:
///   post(op, attrs) -> IppResult   (one IPP round trip; the shell encodes+sends)
/// It sends NOTHING for a printer name it will not build a request for; otherwise
/// it sends a Get-Jobs of the named printer, and sends Cancel-Job ONLY when that
/// listing holds the job id on that printer. Transport, HTTP 401/403, decode and status
/// failures of either request are reported, never turned into a cancel.
template <class Post>
[[nodiscard]] ClearQueueDisposition run_clear_queue(std::string_view printer_as_given, int64_t job_id,
                                                     std::string_view user, const ClearQueueTokens& tok,
                                                     Post&& post) {
    const std::string shown = printer_echo_posix(printer_as_given);
    const auto make = [&](ClearQueueStatus st, bool full, std::string detail, std::string_view outcome,
                          std::string_view token) {
        ClearQueueDisposition d;
        d.rc = st == ClearQueueStatus::ok ? 0 : 1;
        d.status = st;
        d.full = full;
        d.detail = std::move(detail);
        d.row = format_clear_queue_row(shown, job_id, outcome, token);
        return d;
    };

    const std::string name = printer_name_from_operand(printer_as_given);
    if (!printer_name_is_valid_posix(name)) {
        // `shown` is "-" here, not the offending value: it may be arbitrarily long or hold
        // control characters, and it was never used to build a request.
        return make(ClearQueueStatus::unavailable, false, "invalid printer name", "error", "invalid_printer");
    }

    // A round trip that failed before yielding an IPP status is reported the same
    // way for both requests.
    const auto round_trip_failure = [&](const IppResult& r,
                                        std::string_view op) -> std::optional<ClearQueueDisposition> {
        if (!r.transport_ok)
            return make(ClearQueueStatus::unavailable, false, std::format("{}: transport failed", op), "error",
                        tok.connect_failed);
        if (r.http_status == 401 || r.http_status == 403)
            return make(ClearQueueStatus::permission_denied, true, std::format("{}: HTTP auth/forbidden", op),
                        "refused", tok.access_denied);
        if (!r.message)
            return make(ClearQueueStatus::unavailable, false, std::format("{}: response did not decode", op),
                        "error", tok.decode_failed);
        return std::nullopt;
    };

    const IppResult listing = post(ipp::kGetJobs, job_binding_check_attrs(name));
    if (auto failure = round_trip_failure(listing, "Get-Jobs"))
        return *failure;
    const uint16_t listing_status = listing.message->op_or_status;
    const CancelStatusClass listing_cls = classify_cancel_job_status(listing_status);
    if (listing_cls == CancelStatusClass::not_found)
        return make(ClearQueueStatus::unavailable, true, "Get-Jobs: printer not found", "not_found", tok.not_found);
    if (listing_cls == CancelStatusClass::refused)
        return make(ClearQueueStatus::permission_denied, true, "Get-Jobs: not authorized", "refused",
                    tok.access_denied);
    if (listing_cls != CancelStatusClass::canceled) // any other non-successful status
        return make(ClearQueueStatus::unavailable, false,
                    std::format("Get-Jobs: unexpected status 0x{:04x}", listing_status), "error",
                    tok.unexpected_status);
    // Fail closed: ONLY on_printer proceeds, so a verdict added later can never fall through
    // into a Cancel-Job.
    const JobListing verdict = classify_job_listing(jobs_from_ipp(*listing.message), job_id, name);
    if (verdict == JobListing::unconfirmed) // listed, but nothing confirms which printer it is on
        return make(ClearQueueStatus::unavailable, false,
                    "Get-Jobs: the job is listed but its printer could not be confirmed", "error",
                    tok.unexpected_status);
    if (verdict != JobListing::on_printer)
        return make(ClearQueueStatus::unavailable, true, "Get-Jobs: job is not on the named printer's active queue",
                    "not_found", tok.not_found);

    std::vector<ipp::OperationAttr> attrs;
    attrs.push_back({ipp::kTagUri, "printer-uri", printer_uri_for(name), {}});
    attrs.push_back({ipp::kTagInteger, "job-id", ipp::encode_int32(static_cast<int32_t>(job_id)), {}});
    attrs.push_back({ipp::kTagNameWithoutLanguage, "requesting-user-name", std::string(user), {}});
    const IppResult result = post(ipp::kCancelJob, attrs);
    if (auto failure = round_trip_failure(result, "Cancel-Job"))
        return *failure;

    // The job could finish between the two requests (cupsd then answers 0x0404 or
    // 0x0406, reported below). One MOVED to another queue in that window (cupsd's
    // default policy lets the job's owner or an administrator do that) is still
    // cancelled by id: the id the operator named, accepted as a narrow window.
    const uint16_t status = result.message->op_or_status;
    const CancelStatusClass cls = classify_cancel_job_status(status);
    if (cls == CancelStatusClass::canceled)
        return make(ClearQueueStatus::ok, true, "", "canceled", "-");
    if (cls == CancelStatusClass::not_found)
        return make(ClearQueueStatus::unavailable, true, "Cancel-Job: job not found", "not_found", tok.not_found);
    if (cls == CancelStatusClass::refused)
        return make(ClearQueueStatus::permission_denied, true, "Cancel-Job: not authorized", "refused",
                    tok.access_denied);
    return make(ClearQueueStatus::unavailable, false, std::format("Cancel-Job: unexpected status 0x{:04x}", status),
                "error", tok.unexpected_status);
}

/// Accepts ONLY `^[0-9]{1,9}$` with value >= 1 — a printer job id is never
/// negative, never zero, never hex/scientific notation, and a 10+-digit
/// string is refused outright rather than risking a silent 64-bit wrap on a
/// platform where `int64_t` parsing of a huge digit run could overflow. The
/// PUBLISHED definition pattern `^[1-9][0-9]{0,8}$` is deliberately stricter
/// (no leading zeros): the agent still accepts "007" as job 7, which is safe.
[[nodiscard]] inline std::optional<int64_t> parse_job_id(std::string_view s) {
    if (s.empty() || s.size() > 9)
        return std::nullopt;
    for (const char c : s) {
        if (c < '0' || c > '9')
            return std::nullopt;
    }
    int64_t v = 0;
    const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || ptr != s.data() + s.size())
        return std::nullopt;
    if (v < 1)
        return std::nullopt;
    return v;
}

} // namespace yuzu::printing
