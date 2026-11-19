# Resource Ledger - #6090 (package_id on the installed-software read routes)

Run: `6090-package-id-read-routes.pkgid1`. Gate 1 Resource Ledger for the C++ diff.

## Production code (`software_catalogue_model.{cpp,hpp}`, `software_list_model.{cpp,hpp}`, `rest_api_v1.cpp`, `mcp_server.cpp`, comment-only edits in `software_export_routes.cpp` and `software_export_stream.hpp`)

No new or modified owning resource. The change adds one more `std::string` copy of `SoftwareEntry::package_id` into an existing `nlohmann::json` object (`device_row_json`), one into an existing CSV cell list (`installs_csv`) and one more element in an existing `std::array<std::string, kListCsvColumns>` (`list_row_cells`). Each is a value type owned by its local container and released at scope exit.

| Resource | Owner | Acquired | Released / transferred | Failure cleanup |
|---|---|---|---|---|
| none new: file descriptors, handles, sockets, threads, callbacks, temp paths, DB leases and transactions | n/a | n/a | n/a | n/a |
| `std::array` size 23 -> 24 | `kListCsvColumns` constant, tied to the header by an existing `static_assert` | compile time | n/a | a mismatch is a build failure |
| OpenAPI and MCP schema text (`R"json(` literals) | static storage | compile time | n/a | segment size is guarded by `tests/test_openapi_literal_segments.py` |

The value is agent-supplied text already validated at ingest and leaves through the same escaping as its sibling cells (`csv_escape`, the XLSX text-cell writer, `dump_safe`). No store, ingest, hash or migration code changes.
