# Resource Ledger — install-row attributes (SAM-46 part 1)

Range: `0c68ac5043833decce953e5cb3f45d173374d7d1..1866e80940` (branch `feat/sam-46-install-row-attributes`)

Run: `governance.d/sam46-install-row-attributes.QZAMIE.jsonl`

## Summary

This diff introduces **no fd / HANDLE / SOCKET / `FILE*` / `sqlite3*` / OpenSSL object / BCrypt
handle / allocated C string / mapped library / temp path / subprocess / thread / callback
context / stored pointer or reference**, and no `reinterpret_cast`, `const_cast`, `raw()` or
`release()`. Every owned object is a value type (`std::string`, `std::optional`, `std::vector`,
`std::array`) under RAII, or a `constexpr` constant in static storage. The server SQL changes
are statement text and one more text[] parameter: no new connection, transaction, cursor or
statement handle.

## Table 1 — new owned state (all RAII value types or static constants)

| Resource | Type | Owner | Scope | Notes |
|---|---|---|---|---|
| `kAttributeKeys` | `inline constexpr std::array<AttributeKey,1>` | `install_row_attributes.hpp` | static storage, program lifetime | Constant-initialised: a `string_view` of a literal and a `noexcept` function pointer; no static-init-order dependency; strictly ascending by name (`static_assert`). |
| `canonical_attributes` result | `std::optional<std::string>` | the caller's full expression | one call | A copy of the input (`std::string(raw)`); nothing views the argument after return. In the agent the argument is the temporary from `clamp(...)`, alive to the end of the full-expression; in the server parser the result is discarded and `f[14]` is moved only afterwards. |
| `attribute_value` result | `std::string_view` | borrowed from its `canonical` argument | caller's scope | A sub-view of the argument; no production caller (tests only), and each test keeps the backing string alive. |
| `make_attributes` working set (`sorted`, `out`) | `std::vector<std::pair<string_view,string_view>>`, `std::string` | `make_attributes` | function-local, result returned by value | The views point into the caller's pairs, valid for the call; the returned `optional<string>` owns its bytes. |
| `code` and `kv[]` in the MSI adapter | `std::string`, `const std::pair<string_view,string_view>[1]` | the row lambda in `parse_msi_packages_list_inventory_output` | one row iteration | `kv` holds a view of a literal and of the local `code`; both outlive the full-expression `make_attributes(kv).value_or(...)`; the result is an owning string assigned to `e.attributes`. |
| `SwEntry::attributes`, `SoftwareEntry::attributes` | `std::string` members | the entry that holds them | the entry | One more value member; empty values stay in SSO. |
| `cols[20]` (`insert_entries`) | `std::vector<std::string_view>` element | `insert_entries` | function-local | A view of `e.attributes` in the caller's `entries` (const reference, outlives the call); `to_text_array` copies into owned `std::string` parameters before the call returns. |
| `std::size(fields)` pointer table (`read_facet_rows`) | `std::string*[18]` | `read_facet_rows` | one row iteration | Pointers into a local `SoftwareEntry`; 18 entries equal the 18 SELECT columns. |

## Table 2 — pre-existing resources this diff touches without changing ownership

| Resource | Owner | This diff's interaction |
|---|---|---|
| `PGconn*` and `pg::PgResult` in `insert_entries` and `read_facet_rows` | the caller borrows the connection; `PgResult` is the existing move-only RAII owner | One more column in the INSERT (`$22`) and in the SELECT. No new acquisition and no new early-return path; the existing non-OK-status returns carry no manual free. |
| migration ladder transaction (v13) | `pg::PgMigration` runner | One appended constant-default `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`. Runs inside the existing ladder transaction under the pool's 10 s `lock_timeout`; a failure refuses boot (fail-closed); no new handle. |
| `sanitize_utf8_strict` / `scrub_and_clamp` result `f[14]` | the parser's per-record `std::vector<std::string>` | Read by `canonical_attributes`, then moved into `SoftwareEntry::attributes`. |
