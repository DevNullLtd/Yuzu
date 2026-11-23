# Resource Ledger — SAM-29 lifecycle-rule and normalisation-curation MCP twins

Range: `origin/dev..HEAD` (branch `feat/sam-29-lifecycle-mcp`)

## Summary

This diff adds **no store, thread, subprocess, socket, listener, `FILE*`, `sqlite3*`, OpenSSL object,
mapped library or temp path**. Eight MCP tools call two new transport-neutral function families
(`software_lifecycle_api`, `software_curation_api`) that hold the bodies moved out of the REST
routes; both surfaces borrow the two stores the REST routes already borrow
(`SoftwareLifecycleStore`, `ProductRegistryStore`). Request memory is bounded by the MCP body cap
(4 MiB for the whole JSON-RPC request, checked before routing), and by the parsers' own bounds
(import 4,194,304 bytes, pack 1,048,576 bytes, 5,000 rows).

## Table 1 — new owned state

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | `SoftwareLifecycleStore*` and `ProductRegistryStore*` held by `McpServer` (`software_lifecycle_store_`, `product_registry_store_`) | none: raw, borrowed pointers, never deleted by `McpServer` | set once by `ServerImpl` from `software_lifecycle_store_.get()` and `product_registry_store_.get()` (the pointers the REST routes borrow), before the MCP handler is built | never released by `McpServer`; the owners reset them in `stop()` after the web thread is joined, the order the REST routes already depend on | none | an unset pointer answers an internal error with no retry hint; no cleanup |
| R2 | Request-scoped `software_lifecycle_api::Reply` / `software_curation_api::Reply` (a JSON body, a message, a remediation) | value types, stack locals of each tool call | built by the shared function | scope exit of the tool call | moved into the response writer | value types; nothing to release on any path |
| R3 | `lifecycle_import::Parsed` rules of one import, the `ParsedPack` of one pack | `std::vector` / `std::string` locals of `import_rules` and `replace_pack` | built by the parser, bounded by the 4 MiB import / 1 MiB pack bound and 5,000 rows | function exit | borrowed by const reference into the store call | value types; the parse is all or nothing and a refusal leaves nothing behind |
| R4 | `AuditSink` (a `std::function` over a lambda capturing the request and the audit callback by reference) | stack local of the tool call (MCP) or of the route handler (REST) | built per request | scope exit | none | no state of its own; it never outlives the request it references |

## Locks and leases

No lock is added. A store call takes the same pooled connection lease it took inside the REST
route; no lease and no lock is held across an audit write (the `requested` row is written before the
store call and the outcome row after it returns, exactly as the REST routes did). The registry
writes keep their own advisory-lock sequence inside `ProductRegistryStore` (the dimension
invalidation contract); the MCP branch never touches the registry other than through
`curate_alias`, `reject_curation`, `replace_pack` and the two reads.

## Table 2 — pre-existing resources this diff touches without changing ownership

| Resource | Owner | This diff's interaction |
|---|---|---|
| `SoftwareLifecycleRoutes`, `SoftwareCurationRoutes` handlers | route classes | the handler bodies move into the shared functions; each handler keeps the gate, the exactly-once parameter counts, the Content-Type check (pack) and the HTTP mapping. `SoftwareLifecycleRoutes::Deps` and its `server.cpp` initialiser are unchanged. |
| `kMcpStepUpPolicy` / `kMcpKeySlots` | `step_up_mcp_policy.hpp` | five exempt rows; the compile-time tool-name index grows from 256 to 512 slots because the table passed 85 rows (a `consteval` local array, no runtime state). |
