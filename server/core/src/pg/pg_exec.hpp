#pragma once

/// @file pg_exec.hpp
/// Parameterized-query helpers shared by every Postgres-backed store — the
/// public home of the single-param `exec_param` pattern that was seeded
/// inside the migration runner (#1368 "promote exec_params into pg/"). All
/// values bind through libpq's positional `$1, $2, …` parameters
/// (`PQexecParams`), so store SQL never string-concatenates untrusted input
/// and the #1033 hand-rolled-PQexecParams boilerplate does not accrete across
/// the ~27 stores still to migrate.
///
/// Result format is text (`resultFormat = 0`); callers read columns with
/// `PQgetvalue` and check `.ok()` / `.status()` on the returned `PgResult`.

#include "pg_raii.hpp"

#include <libpq-fe.h>

#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::pg {

namespace detail {

/// 1-based position of the first parameter holding an embedded NUL byte, or 0 when none does.
/// libpq binds a text-format parameter as a C string (`paramLengths` is not honoured for text
/// format), so a NUL would silently end the value early instead of reaching the server.
[[nodiscard]] inline int first_param_with_nul(
    const std::vector<std::optional<std::string>>& params) noexcept {
    int pos = 1;
    for (const auto& p : params) {
        if (p && p->find('\0') != std::string::npos)
            return pos;
        ++pos;
    }
    return 0;
}

/// Fail-closed result for a refused parameter: the server's own error for a character that
/// cannot be stored in text (SQLSTATE 22021), raised without executing the caller's statement
/// and without echoing the value. Going through the connection keeps every caller's existing
/// failure handling intact: an open transaction aborts exactly as it would for any failed
/// statement, `PQerrorMessage(conn)` and `PQresultErrorMessage` carry the message, and the
/// status is a fatal error. `index` is a decimal integer, never caller text.
[[nodiscard]] inline PgResult refuse_param(PGconn* conn, int index) {
    const std::string sql = "DO $yuzu_param$ BEGIN RAISE EXCEPTION 'parameter $" +
                            std::to_string(index) +
                            " contains a NUL byte' USING ERRCODE = '22021'; END $yuzu_param$";
    return PgResult{PQexec(conn, sql.c_str())};
}

} // namespace detail

/// Execute `sql` binding text-format parameters positionally to `$1..$N`. A
/// null `std::optional` binds SQL NULL; a set one binds its bytes. `conn` must
/// be a live connection — typically a non-empty `PgPool` lease's `get()`. The
/// caller-owned `params` must outlive only this call (the value pointers point
/// into it and are consumed synchronously by `PQexecParams`).
///
/// A parameter containing an embedded NUL byte is refused: the call returns a failed result
/// (SQLSTATE 22021, "parameter $N contains a NUL byte") and the statement is not executed.
/// Every `std::string` overload funnels through this one, so there is a single check. Only NUL
/// is refused: tab, newline, escape and the rest of the control range are valid text and are
/// bound unchanged. Callers that already sanitize or validate NUL out of their input are
/// unaffected; callers that did not were previously handed a silently truncated value.
inline PgResult exec_params(PGconn* conn, const char* sql,
                            const std::vector<std::optional<std::string>>& params) {
    if (const int bad = detail::first_param_with_nul(params); bad != 0)
        return detail::refuse_param(conn, bad);
    const int n = static_cast<int>(params.size());
    std::vector<const char*> values;
    values.reserve(params.size());
    for (const auto& p : params)
        values.push_back(p ? p->c_str() : nullptr);
    return PgResult{PQexecParams(conn, sql, n, /*paramTypes=*/nullptr,
                                 n > 0 ? values.data() : nullptr,
                                 /*paramLengths=*/nullptr, /*paramFormats=*/nullptr,
                                 /*resultFormat=*/0)};
}

/// Convenience overload for the common all-non-null-string case.
inline PgResult exec_params(PGconn* conn, const char* sql,
                            const std::vector<std::string>& params) {
    std::vector<std::optional<std::string>> opt;
    opt.reserve(params.size());
    for (const auto& p : params)
        opt.emplace_back(p);
    return exec_params(conn, sql, opt);
}

} // namespace yuzu::server::pg
