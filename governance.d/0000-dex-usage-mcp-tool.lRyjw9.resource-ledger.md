# Resource Ledger — fleet application usage MCP tool

Range: `origin/dev..HEAD` (branch `feat/dex-usage-mcp`)

Recorded by: Doomgoose

## Summary

This diff introduces **no thread, subprocess, socket, `FILE*`, `sqlite3*`, OpenSSL object, BCrypt
handle, mapped library, lock or temp path**. It adds one `std::function` member to
`mcp::ToolDeps` that forwards to the `DexApi` the REST usage route already uses, one handler that
runs synchronously inside one `tools/call` request, and three pure functions (a refusal
classifier, an argument parser and an audit-detail formatter) that hold no state.

## Table 1 — new owned state

| Resource | Type | Owner | Scope | Notes |
|---|---|---|---|---|
| `ToolDeps::dex_apps_usage_fn` | `std::function` capturing one `std::shared_ptr<DexApi>` copy | `McpServer::tool_deps_` | server lifetime | The copy is the same object `McpServer::dex_api_` already holds (+1 refcount, released with the `ToolDeps`). It is wired only when the deployment has a `DexApi` and is empty otherwise, so the handler answers an internal error rather than an empty result. It applies no permission or audit rule: the handler gates and audits before calling it. Each call builds its answer on the calling thread and keeps nothing after it returns. |
| `handle_get_dex_apps_usage` locals | `DexUsageMcpRequest`, `std::expected<DexAppsUsageModel, DexUsageRefusal>`, `std::string` bodies | handler stack frame | one `tools/call` | Request-frame objects only: never stored, never shared across threads, destroyed with the frame. |

## Table 2 — pre-existing resources this diff touches without changing ownership

| Resource | Owner | This diff's interaction |
|---|---|---|
| `DexApi::apps_usage` read, its 30-second answer cache and its concurrency budget | the `DexApi` implementation | Called exactly as the REST route calls it; the MCP path adds no cache, lock or budget of its own and takes the same budget slot a REST read takes. |
| `ToolDeps::audit_fn` | `McpServer::tool_deps_` | One `dex.apps.usage.view` row per admitted call through the shared `try_persist_audit` kernel, which catches a throwing sink and counts it as a dropped row. No new sink. |
| `ToolDeps::fleet_read_fn` | `McpServer::tool_deps_` | One `Forensics:Read` call per request; the returned scope is passed to the read by value-reference for that call only. |
| the REST usage route's refusal answer | `RestApiV1` | Calls the shared classifier in place of its inline table; no new state. |

## Tests

Test code adds Catch2 locals (fake closures, `std::vector` event and audit logs, an `McpServer` and
its handler). No real file, process, socket or Postgres connection is opened.
