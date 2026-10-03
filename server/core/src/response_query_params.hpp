#pragma once

/// @file response_query_params.hpp
/// Strict numeric query-parameter parsing shared by the legacy
/// `GET /api/responses/{id}[/aggregate|/export]` routes (response_routes.cpp) and the
/// REST v1 response routes (rest_api_v1.cpp), plus the export-body byte cap both
/// export surfaces enforce (#4644, #4703).
///
/// Why this exists: those routes parsed `status`/`since`/`until`/`limit`/`offset`
/// with `std::stoi`/`std::stoll`, which accept leading digits followed by anything
/// (`stoi("0x1")` -> 0, `stoll("1e9")` -> 1, `stoi("100abc")` -> 100), so a
/// malformed value silently became a different, valid-looking filter (`?since=1e9`
/// meant "since epoch second 1", `?status=0x1` meant status 0). Empty values and
/// overflow already 400'd (`stoi("")` threw); what is new is rejecting every value that
/// is not ONE base-10 integer, and `status < -1`.
///
/// Pure and I/O-free: no httplib.h, no store access. The caller supplies a getter so
/// this header never sees the request type.

#include <atomic>
#include <charconv>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>

#include "response_store.hpp"

namespace yuzu::server {

/// Full-consumption signed-integer parse: the WHOLE string must be one base-10
/// integer. Rejects empty, trailing garbage ("100abc", "1e9", "0x1"), embedded or
/// surrounding whitespace, a leading '+', and out-of-range values (no wraparound,
/// no clamping). A leading '-' is accepted (the range check is the caller's), and
/// zero-padding ("007") is accepted -- a client legitimately sending `status=007`
/// is not malformed, unlike a stored value that must round-trip.
template <typename T>
[[nodiscard]] std::optional<T> parse_query_int(std::string_view s) {
    static_assert(std::is_integral_v<T> && std::is_signed_v<T>);
    T v{};
    const char* const begin = s.data();
    const char* const end = begin + s.size();
    const auto [ptr, ec] = std::from_chars(begin, end, v);
    if (ec != std::errc{} || ptr != end)
        return std::nullopt;
    return v;
}

/// The `status` filter's domain: -1 is the documented "any status" sentinel
/// (ResponseQuery's default); 0.. selects one CommandResponse status. Anything
/// below -1 is neither -- ResponseStore only applies the filter when status >= 0, so
/// `status=-5` used to behave exactly like "no filter" while looking like a filter.
[[nodiscard]] inline bool is_valid_response_status_filter(int status) noexcept {
    return status >= -1;
}

/// Which numeric parameters a route accepts.
enum ResponseNumericParam : unsigned {
    kRespParamStatus = 1u << 0,
    kRespParamSince = 1u << 1,
    kRespParamUntil = 1u << 2,
    kRespParamLimit = 1u << 3,
    kRespParamOffset = 1u << 4,
};

/// Apply every numeric parameter named in `accepted` that the request actually
/// carries onto `q`. `Req` is anything with httplib's `has_param(name)` /
/// `get_param_value(name)` (duck-typed so this header never includes httplib.h). An
/// EMPTY value (`?limit=`) is present and malformed.
///
/// Returns false on the first malformed or out-of-domain value; `q` may then be
/// partially filled and must not be used -- the caller answers its own route's 400
/// and returns. `since`/`until` get no range check: the stores treat 0 as "unbounded
/// that side" and a negative epoch is meaningless but harmless, so the only contract
/// enforced is "is a number".
template <typename Req>
[[nodiscard]] bool apply_response_numeric_params(const Req& req, ResponseQuery& q,
                                                 unsigned accepted) {
    const auto get_int = [&req](const char* name, auto& out, auto&& valid) -> bool {
        if (!req.has_param(name))
            return true;
        using T = std::remove_reference_t<decltype(out)>;
        const auto v = parse_query_int<T>(req.get_param_value(name));
        if (!v || !valid(*v))
            return false;
        out = *v;
        return true;
    };
    const auto any = [](auto) { return true; };
    return (!(accepted & kRespParamStatus) ||
            get_int("status", q.status,
                    [](int v) { return is_valid_response_status_filter(v); })) &&
           (!(accepted & kRespParamSince) || get_int("since", q.since, any)) &&
           (!(accepted & kRespParamUntil) || get_int("until", q.until, any)) &&
           (!(accepted & kRespParamLimit) || get_int("limit", q.limit, any)) &&
           (!(accepted & kRespParamOffset) || get_int("offset", q.offset, any));
}

/// Row-count ceiling AND default for one export, shared by the legacy and v1 export
/// handlers so the two cannot drift (the legacy route used to clamp only its default).
inline constexpr int kExportRowLimitCap = 10000;

/// Row-count ceiling for the plain (non-export) list routes: the legacy
/// `GET /api/responses/{id}` used to pass an explicit `limit` straight to the store, so
/// `?limit=2147483647` was an unbounded fetch while its v1 and MCP twins clamp to this.
inline constexpr int kQueryRowLimitCap = 1000;

/// Apply the plain-list ceiling: a `limit` above `kQueryRowLimitCap` is clamped down.
/// A non-positive value is deliberately left alone -- the store maps it to its default
/// (100), which is this legacy route's long-standing meaning for `limit<=0`; only the
/// missing ceiling is fixed here, not that.
[[nodiscard]] inline int cap_query_limit(int requested) {
    return requested > kQueryRowLimitCap ? kQueryRowLimitCap : requested;
}

/// Normalise an export `limit`: a caller-supplied value is clamped to
/// `[1, kExportRowLimitCap]`, an omitted one defaults to the cap. One definition so
/// the legacy and v1 export handlers cannot drift, and so the exact ceiling is
/// observable in a pure unit test without storing 10,001 rows.
[[nodiscard]] inline int normalize_export_limit(bool supplied, int requested) {
    return supplied ? (requested < 1 ? 1 : (requested > kExportRowLimitCap ? kExportRowLimitCap : requested))
                    : kExportRowLimitCap;
}

/// Ceiling on the ROW PAYLOAD BYTES of one export, on top of the row-count cap: the
/// cumulative `output` + `error_detail` size of the rows served. It is enforced in TWO
/// places that share this one constant:
///   1. in SQL (`ResponseStore::query_bounded`), so the fetch itself -- libpq's
///      PGresult and the parsed vector -- holds this much payload plus one final row
///      (a row is kept while the rows BEFORE it are under the cap, so the last kept row
///      can run past it by up to its own size, about 4 MiB: each of the two fields is
///      capped at 2 MiB at ingest) and never materialises the rest; and
///   2. at serialization (`append_rows_until_byte_cap`) as a backstop, because CSV
///      escaping and JSON framing make the SERIALIZED row larger than its raw payload.
/// Both cut on whole rows and always serve at least one row. What this does NOT bound:
/// the plain list routes (`GET .../responses/{id}`, MCP `query_responses` and
/// `GET /api/v1/executions/{id}/responses`: each at most 1000 rows, no byte bound), the
/// execution visualization route (`query()` with a 10,000-row limit), and the dashboard
/// `/fragments/results` and scan-page fetches (`query()` with limit 10,000); none of
/// those goes through `query_bounded`.
/// A flat constant local to the export surface -- NOT the ingest cap, which bounds a
/// different thing -- and not operator-tunable. Well above any realistic export (a
/// 10,000-row export of typical command output is a few MiB).
inline constexpr std::size_t kExportBodyByteCap = 50u * 1024u * 1024u;

/// Test seam over `kExportBodyByteCap`: production reads the default; a unit test
/// lowers it so truncation is reachable without building a 50 MiB body. One instance
/// shared by the legacy and v1 export handlers (inline function-local static: a single
/// object across every TU that includes this header).
inline std::atomic<std::size_t>& export_body_byte_cap() {
    static std::atomic<std::size_t> cap{kExportBodyByteCap};
    return cap;
}

/// Why an export was cut. Both can be set; `cause()` names the tighter one.
struct ExportCut {
    bool row_cap{false};  ///< more matching rows existed beyond `limit`
    bool byte_cap{false}; ///< rows within `limit` were left out by the payload cap
    [[nodiscard]] bool any() const noexcept { return row_cap || byte_cap; }
    /// Closed metric-label value (`yuzu_server_response_export_truncated_total{cause}`).
    [[nodiscard]] const char* cause() const noexcept { return byte_cap ? "byte_cap" : "row_cap"; }
};

/// `Content-Disposition` filename: a cut export is renamed `-truncated`, a second
/// out-of-body signal beside the `X-Result-Truncated-By-Cap` header. It survives
/// `curl -OJ` and a browser download, but NOT a plain `curl -o <name>` (curl then names
/// the file itself and discards the header); the CSV body therefore also carries an
/// in-band trailer row on a cut (`export_csv_truncation_row`).
///
/// The id is written into a quoted header value, so anything outside `[A-Za-z0-9._-]`
/// (a quote, CR/LF, a path separator, a non-ASCII byte) is replaced by `_`: the legacy
/// route's id pattern is `[^/]+`, i.e. unrestricted, where the v1 routes only admit
/// `[A-Za-z0-9_-]{1,128}`.
[[nodiscard]] inline std::string export_filename(std::string_view instruction_id,
                                                 std::string_view ext, bool truncated) {
    std::string n = "responses-";
    for (const char c : instruction_id) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        n += ok ? c : '_';
    }
    n += truncated ? "-truncated." : ".";
    n += ext;
    return n;
}

/// In-band truncation marker for a CUT CSV export: one extra record after the data
/// rows, with `columns` fields so a positional parser still sees a rectangular file.
/// The first field is `# result_truncated_by_cap cause=<row_cap|byte_cap>` and the rest
/// are empty. A cut CSV is the one case where a consumer must NOT take the file as
/// complete, so a strict parser that trips on the non-numeric id field is the intended
/// outcome; an uncut export never carries it (byte-identical to the pre-#4703 body).
/// Appended after the byte-cap backstop decision, so it is not counted against the cap.
[[nodiscard]] inline std::string export_csv_truncation_row(const ExportCut& cut,
                                                           std::size_t columns) {
    std::string row = "# result_truncated_by_cap cause=";
    row += cut.cause();
    for (std::size_t i = 1; i < columns; ++i)
        row += ',';
    row += "\r\n";
    return row;
}

/// Append rows to an export body until the running byte total reaches `cap`, then stop.
/// `append(row)` adds one row's bytes to the body and returns that body's new total
/// size. Returns true when rows were left out (i.e. the body is truncated by the byte
/// cap) -- false when every row fit, including when the LAST row is the one that
/// crosses the cap (nothing was dropped, so no truncation signal). At least one row is
/// always emitted, so a single row larger than a test-lowered cap still makes progress.
/// The returned total is whatever `append` reports (CSV: the whole body incl. header;
/// JSON: the serialized row objects only) -- a backstop to the SQL cut, not an exact
/// body-size limit.
template <typename Rows, typename Append>
[[nodiscard]] bool append_rows_until_byte_cap(const Rows& rows, std::size_t cap, Append&& append) {
    std::size_t i = 0;
    for (const auto& r : rows) {
        const std::size_t total = append(r);
        ++i;
        if (total >= cap && i < rows.size())
            return true;
    }
    return false;
}

}  // namespace yuzu::server
