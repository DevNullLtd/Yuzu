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

} // namespace yuzu::server::pg
