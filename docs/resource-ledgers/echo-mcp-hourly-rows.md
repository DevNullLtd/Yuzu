# Resource Ledger: Echo retention-paused row count rename (`live_rows` to `hourly_rows`)

Range: the `feat/echo-mcp-hourly-rows` commits. The C++ in this change renames a field and a
JSON key and edits string literals and tests.

## Resources

None introduced or modified. No fd, HANDLE, SOCKET, `FILE*`, `sqlite3*`/`sqlite3_stmt*`, OpenSSL
or BCrypt object, allocated C string, mapped library, temp path, subprocess, callback context or
thread is acquired, released, transferred or changed by this change.

## Touched code, for the record
- `EchoPausedSourceRow::hourly_rows` (`echo_tree_routes.hpp`): a plain `std::int64_t` member of a
  value-type struct (was `live_rows`). Value-owned by the scan vector; no lifetime change.
- `echo_retention_paused_json` (`echo_tree_routes.cpp`) and `gather_echo_retention_paused` /
  `render_echo_retention_paused` (`dashboard_routes.cpp`): the field name only.
- `mcp_server.cpp` and `rest_api_v1.cpp`: static string literals (tool description, output
  schema, OpenAPI document text); program-lifetime, no ownership.
