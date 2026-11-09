# Resource Ledger — MCP DEX score policy twins (#6087)

Range: `origin/dev..HEAD` (branch `feat/mcp-dex-score-policy`)

## Summary

This diff introduces **no thread, subprocess, socket, `FILE*`, `sqlite3*`, OpenSSL object, BCrypt
handle, mapped library or temp path**. It adds two `std::function` members to `mcp::ToolDeps` that
forward to state the REST score policy routes already own, and three handlers that run
synchronously inside one `tools/call` request.

## Table 1 — new owned state

| Resource | Type | Owner | Scope | Notes |
|---|---|---|---|---|
| `ToolDeps::dex_score_policy_read_fn` | `std::function` (copy of `DexScorePolicyWriteDeps::read_stored`) | `McpServer::tool_deps_` | server lifetime | Borrows `runtime_config_store_` by reference through the store reader (R4 of the score-policy writer ledger, #6086). The store outlives it: `stop()` joins the listener threads before `runtime_config_store_.reset()`, so no MCP handler is running when the reference dies — the REST route relies on the same ordering. |
| `ToolDeps::dex_score_policy_apply_fn` | `std::function` capturing a `DexScorePolicyWriteDeps` copy by value | `McpServer::tool_deps_` | server lifetime | The copy holds the store reader and two conditional-write closures (same store reference as above) and one `shared_ptr<DexScorePolicyProvider>` (+1 refcount, released with the `ToolDeps`). Each call copies the deps, installs the per-request audit hook and calls `apply_dex_score_policy`; the copy dies at the end of the call. |
| `dex_score_policy_deps` | `std::optional<DexScorePolicyWriteDeps>` | `ServerImpl` start-up frame (`server.cpp`) | function-local | Built once, copied into the REST setter and the two closures; the local is dropped when the frame returns, the copies live as above. |
| audit hook | lambda capturing `const ToolCallContext&` and a local `bool&` by reference | `handle_set_dex_score_policy` / `handle_reset_dex_score_policy` | one `apply` call | Wrapped in a `std::function` and passed by value into the apply closure. It is never stored past the call and never crosses a thread; the `bool` and the context are request-frame objects that outlive the handler call (the `ToolCallContext` LIFETIME rule). |

## Table 2 — pre-existing resources this diff touches without changing ownership

| Resource | Owner | This diff's interaction |
|---|---|---|
| `DexScorePolicyProvider` writer lock | provider | Taken inside `apply_dex_score_policy` exactly as for REST; the MCP path adds no second lock and no lock order. |
| approval ticket | `ApprovalManager` | `reset_dex_score_policy` is registered as `Infrastructure:Delete`; the existing generic gate mints and consumes the ticket before the handler runs. No new acquisition; a post-consumption failure spends the ticket by design, documented in the tool description. |

## Tests

Test code adds Catch2 locals only (an in-memory `std::optional<std::string>` store, `std::vector`
audit logs, a `McpServer` and its handler). The approval round trip uses the existing
`ApprovalManagerPg` bundle and skips without a Postgres DSN.
