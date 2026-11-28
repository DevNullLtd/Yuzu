#pragma once

/// @file pg_server_encoding.hpp
/// Boot-time check that the PostgreSQL database encoding is UTF8 (WARN-ONLY by design).
///
/// Several server surfaces re-serialise stored text with a STRICT JSON dump (it throws on invalid
/// UTF-8) and rely on Postgres TEXT rejecting invalid byte sequences at INSERT. That holds only
/// for a UTF8 database. In a SQL_ASCII database (or any non-UTF8 encoding) PG stores arbitrary
/// bytes, so agent-supplied bytes could reach those dumps. The check reads libpq's reported
/// `server_encoding` parameter (no query) from the probe connection. It never stops the server:
/// refusing to boot is an owner decision still pending, so this only logs and exports a gauge.

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>

#include <string>
#include <string_view>

namespace yuzu::server::pg {

/// libpq's reported `server_encoding` for `conn` ("" when unknown or `conn` is null).
[[nodiscard]] inline std::string server_encoding_of(PGconn* conn) {
    if (conn == nullptr)
        return {};
    const char* v = PQparameterStatus(conn, "server_encoding");
    return v != nullptr ? std::string(v) : std::string{};
}

/// True for "UTF8" / "UTF-8" in any case. An unknown ("") encoding is NOT UTF8: fail loud.
[[nodiscard]] inline bool server_encoding_is_utf8(std::string_view enc) noexcept {
    std::string norm;
    for (const char c : enc) {
        if (c == '-' || c == '_')
            continue;
        norm += static_cast<char>((c >= 'a' && c <= 'z') ? c - 'a' + 'A' : c);
    }
    return norm == "UTF8";
}

/// Reads the connection's encoding, describes and sets the gauge `yuzu_pg_server_encoding_not_utf8`
/// (1 when it is not UTF8, else 0) and returns the encoding name through `enc_out`. Returns true
/// when the encoding is UTF8. The caller logs; this only owns the metric, so the assignment is
/// unit-testable (a deleted assignment leaves the gauge at its default and fails the test).
inline bool report_server_encoding(PGconn* conn, yuzu::MetricsRegistry& metrics,
                                   std::string* enc_out = nullptr) {
    const std::string enc = server_encoding_of(conn);
    const bool utf8 = server_encoding_is_utf8(enc);
    metrics.describe("yuzu_pg_server_encoding_not_utf8",
                     "1 if the PostgreSQL database encoding is not UTF8 (agent bytes are then not "
                     "rejected by the database), else 0",
                     "gauge");
    metrics.gauge("yuzu_pg_server_encoding_not_utf8").set(utf8 ? 0.0 : 1.0);
    if (enc_out != nullptr)
        *enc_out = enc;
    return utf8;
}

} // namespace yuzu::server::pg
