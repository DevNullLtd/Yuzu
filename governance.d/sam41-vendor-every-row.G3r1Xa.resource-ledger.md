# Resource Ledger — installed-software publisher on every row

Range: `1d3bc3ea965665a39e8226b72e3afdabbc4fbfea..7ec93256f` (branch `feat/sam-41-vendor-every-row`)

Run: `governance.d/sam41-vendor-every-row.G3r1Xa.jsonl`

## Summary

This diff introduces **no fd / HANDLE / SOCKET / `FILE*` / `sqlite3*` / OpenSSL object / BCrypt
handle / allocated C string / mapped library / temp path / subprocess / thread / callback
context / stored pointer or reference**, and no `reinterpret_cast`, `const_cast`, `raw()` or
`release()`. Every owned object is a value-type `std::string` (or a `constexpr` constant in
static storage) under RAII. The one subprocess it touches (the rpm query in
`get_inventory_linux`) already existed; only its compile-time argv literal gains a trailing
`\t%{VENDOR}` column. The server SQL changes are statement text only: no new connection,
transaction, cursor or statement handle.

## Table 1 — new owned state (all RAII value types or static constants)

| Resource | Type | Owner | Scope | Notes |
|---|---|---|---|---|
| `out` (in `unescape_pipes`) | `std::string` | `unescape_pipes` (`sync_source_installed_software.cpp`) | function-local, returned by value | Reserved to `t.size()`; the `\|` look-ahead reads `t[i + 1]` only after `i + 1 < t.size()`. The input is a `std::string_view` token of the captured line; the result is a fresh copy, so nothing views the capture after the call. The caller passes the temporary straight into `clamp_field(std::string_view, ...)`, which returns a `std::string` by value. |
| `e.publisher` | `std::string` member of `SwEntry` | `vendor_or_origin` / the adapters | the `SwEntry` in the collector's `rows.entries` / `all` vectors | Written in place by `vendor_or_origin` (`std::string(kOriginLabelPrefix) + (ecosystem.empty() ? "unknown" : ecosystem)`: the conditional yields a `std::string` prvalue, never a reference to a temporary). No view of it is retained. |
| `kOriginLabelPrefix` (agent and server copies) | `inline constexpr std::string_view` | static storage of the two headers | program lifetime | Constant-initialised, no static-init-order dependency; the two copies are in different namespaces (`yuzu::agent`, `yuzu::server`) and are pinned equal by tests. |
| `kPythonVendorColumnIsVendor` | `inline constexpr bool` | `sync_source_installed_software.hpp` | program lifetime | `#if defined(__APPLE__)` selects false. |
| `vendor_column_is_vendor` | `bool` lambda capture | the `OnRow` lambda in `parse_runtimes_python_output` | one `adapt_pkg_inventory` call | Captured BY VALUE into a template-parameter callable (`template <class OnRow>`, not `std::function`): no heap, no reference to the enclosing frame. The lambda does not outlive the call. |
| `rpm_text_value` result / `r.publisher` | `std::string` | `parse_rpm_inv_line` (`installed_apps_inventory.hpp`) | function-local, moved into the returned `std::optional<InvRecord>` | Tokens are `string_view`s of the line (`split_tabs`, which always yields at least one token); the ten-token check precedes every `tok[N]` index (`tok[9]`, `tok[5]`). |
| `is_origin_label` / `representative_publisher` results | `std::string` | `software_inventory_store.cpp` | full expression | SQL text built from a compile-time constant prefix and a literal column name; no caller-supplied value is interpolated. The result bound to `q_arms`'s `std::string_view` parameter is a temporary that lives to the end of the enclosing `sql += q_arms(...)` statement, and `q_arms` copies it. `static_assert` pins that the prefix holds no LIKE metacharacter. |
| `pubs_sql` | `std::string` | `refresh_catalog_rollup` | the refresh lambda's frame | `.c_str()` goes to `pg::exec_params(PGconn*, const char* sql, ...)`, which runs the synchronous `PQexecParams` and keeps no pointer after returning; `pubs_sql` outlives the call. |
| rollup INSERT text | `std::string` temporary | `refresh_catalog_rollup` | one `cmd(const std::string&)` call | Built by concatenation including `representative_publisher("publisher")`; `cmd` uses `sql.c_str()` during the call only. |

## Table 2 — pre-existing resources this diff touches without changing ownership

| Resource | Owner | This diff's interaction |
|---|---|---|
| rpm `-qa` subprocess (`installed_apps/get_inventory_linux#2`) | `run_tool` → `yuzu::agent::run_bounded_subprocess` | The compile-time literal argv (`path`, `-qa`, `--queryformat`, format literal) gains `\t%{VENDOR}` as a tenth column; `docs/agent-spawn-sink-manifest.md` pins the same literal. Direct argv, no shell, bounded runner; no `popen`/`system` introduced. Output still lands in `res.output` and is parsed via `std::istringstream`. |
| catalogue-rollup transaction | `pool_.with_txn_for(kQueryAcquireTimeout, ...)` in `SoftwareInventoryStore::refresh_catalog_rollup` | Statement text only (representative publisher expression; KPI publisher count excludes `via:%`). The same single transaction rolls back on any failure, keeping the last good rollup. `pg::PgResult` values stay RAII. |
| `SoftwareTitleDimension::reconcile_queue` | its own `with_txn_for` | Not edited. A change of the `normalize_vendor`/publisher inputs can make the existing prune `DELETE` remove a larger set of open queue rows in one statement; it runs under the transaction's `SET LOCAL statement_timeout` and the advisory lock, and a timeout rolls the whole reconcile back. No new acquisition. |
| `SwEntry::publisher` collector loop | `make_installed_software_source` | One added call, `vendor_or_origin(e)`, per entry already owned by the loop. |

## Tests

New Catch2 tests use only locals (`std::string`, `std::set`, `std::map`, `std::vector`) and
`constexpr const char*` golden digests. No temp file, thread, sleep, subprocess or `string_view`
into a temporary is introduced; the loop `for (const std::string agent : {"h1", ""})` copies each
element into a `std::string`. The `[pg]` cases use the shared pre-migrated template store
(`SWINV_SHARED`), not per-test DDL. The inventory-sync collector test drives the existing
`g_fake` plugin doubles and the real adapter functions.
