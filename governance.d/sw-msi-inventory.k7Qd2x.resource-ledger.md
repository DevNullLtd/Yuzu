# Resource Ledger — msi_packages list_inventory

Range: `origin/dev..HEAD` (branch `feat/sw-msi-inventory`)

## Summary

This diff introduces **no fd / HANDLE / SOCKET / `FILE*` / `sqlite3*` / OpenSSL object / BCrypt
handle / allocated C string / mapped library / temp path / subprocess / thread**. The Windows
Installer enumeration and property calls (`MsiEnumProductsExW`, `MsiGetProductInfoExW`) return
into caller-owned buffers and hand back nothing that must be closed. Every owned object is a
value type under RAII.

## Table 1 — new owned state (all RAII value types)

| Resource | Type | Owner | Scope | Notes |
|---|---|---|---|---|
| `code` | `wchar_t[39]` (stack) | `enumerate_machine_products` | function-local | A `{GUID}` is 38 characters plus the NUL; written by `MsiEnumProductsExW`, converted to UTF-8 per product before the next call. |
| `buf` | `std::wstring` | `read_product_property` | function-local | Starts at 256 wide characters; on `ERROR_MORE_DATA` it is re-sized ONCE to the API-reported length + 1 (the reported length excludes the NUL), but only when that length is at most 4096 characters; a longer value fails the read (`windows:msi_prop:oversized`) instead of allocating whatever the OS reports. The collector's `clamp_field` then bounds what is stored. |
| `wcode` / `wprop` | `std::wstring` | `read_product_property` | function-local | UTF-8 to UTF-16 copies of the product code and property name via `yuzu::win::to_wide`; the pointers passed to the API do not outlive the call. |
| `Inventory` / `Product` | `std::vector<Product>` of `std::string` members | `do_list_inventory` | function-local | Built, rendered to `std::vector<std::string>`, moved into `ctx.write_output`; nothing escapes the frame. |

## Table 2 — pre-existing resources this diff touches without changing ownership

| Resource | Owner | This diff's interaction |
|---|---|---|
| plugin `execute()` | `MsiPackagesPlugin` | One `try { ... } catch (...) { ... }` now wraps the whole body (it had none). The catch writes a fixed-token status row inside its own nested `try`/`catch (...)`, so it cannot throw. No new acquisition. |

## Tests

Test code adds only Catch2 locals (`std::vector`, `std::set`, `std::string`). The Windows-only
block calls `MsiEnumProductsExW` into a stack `wchar_t[39]` and owns nothing else; the fixture
reader is a scoped `std::ifstream`.
