# Resource Ledger — MCP DEX score policy twins (#6087)

Range: `origin/dev..HEAD` (branch `feat/mcp-dex-score-policy`)

## Summary

This diff introduces **no thread in production code, and no subprocess, socket, `FILE*`,
`sqlite3*`, OpenSSL object, BCrypt handle, mapped library or temp path**. It adds four
`std::function` members to `mcp::ToolDeps` (two forward to state the REST score policy routes
already own, two resolve and audit as the caller's session) and three handlers that run
synchronously inside one `tools/call` request. The test file adds exactly one thread, owned by one
Catch2 test frame (Table 1, last row).

## Table 1 — new owned state

| Resource | Type | Owner | Scope | Notes |
|---|---|---|---|---|
| `ToolDeps::dex_score_policy_read_fn` | `std::function` (copy of `DexScorePolicyWriteDeps::read_stored`) | `McpServer::tool_deps_` | server lifetime | Borrows `runtime_config_store_` by reference through the store reader (R4 of the score-policy writer ledger, #6086). The store outlives it: `stop()` joins the listener threads before `runtime_config_store_.reset()`, so no MCP handler is running when the reference dies (or the join bound expires and the process `_Exit`s, running no destructors at all) — the REST route relies on the same ordering. |
| `ToolDeps::dex_score_policy_apply_fn` | `std::function` capturing a `DexScorePolicyWriteDeps` copy by value | `McpServer::tool_deps_` | server lifetime | The copy holds the store reader and two conditional-write closures (same store reference as above) and one `shared_ptr<DexScorePolicyProvider>` (+1 refcount, released with the `ToolDeps`). Each call copies the deps, installs the per-request audit hook and calls `apply_dex_score_policy`; the copy dies at the end of the call. |
| `ToolDeps::session_fn` | `std::function` wrapping a lambda that captures `this` (`ServerImpl`) and calls `auth_routes_->resolve_session(req)` | `McpServer::tool_deps_` | server lifetime | Borrows `ServerImpl::auth_routes_` through `this`, exactly as the existing `username_fn` does: the `AuthRoutes` is a `unique_ptr` member never reset before the `ServerImpl` is destroyed, which happens after `stop()` has joined the listener threads, so no handler runs once it dies. Called once per write, from the handler's own request frame. |
| `ToolDeps::audit_as_session_fn` | `std::function` returned by `AuthRoutes::audit_as_session_fn()` (a lambda over the `AuthRoutes` raw `this`) | `McpServer::tool_deps_` | server lifetime | The documented contract of that factory: the `AuthRoutes` is owned by `ServerImpl` and outlives every call. The REST routes and the Settings routes hold the same closure type from the same factory. Each call forwards the session and the role the handler captured, to `AuditStore` through `audit_log_for_session`; nothing is retained after it returns. |
| `WriterIdentity` | struct holding an `auth::Session` copy (by value) and the role string | `handle_set_dex_score_policy` / `handle_reset_dex_score_policy` stack frame | one `tools/call` | Built once by `writer_identity` (the session resolved once, the effective role read once) and borrowed by reference by the audit hook for the single synchronous `apply` call; destroyed with the handler frame, never stored, never shared across threads. |
| `dex_score_policy_deps` | `std::optional<DexScorePolicyWriteDeps>` | `ServerImpl` start-up frame (`server.cpp`) | function-local | Built once, copied into the REST setter and the two closures; the local is dropped when the frame returns, the copies live as above. |
| audit hook | lambda capturing `const ToolCallContext&`, the handler's `WriterIdentity` and a local `bool&` by reference | `handle_set_dex_score_policy` / `handle_reset_dex_score_policy` | one `apply` call | Wrapped in a `std::function` and passed by value into the apply closure. It is never stored past the call and never crosses a thread; the `bool`, the identity and the context are request-frame objects that outlive the handler call (the `ToolCallContext` LIFETIME rule). Inside it, a `std::function` adapter that binds the session and role to the session-bound writer is a call-local, built and destroyed per row; a throwing writer is caught by the shared `try_persist_audit` kernel and counts as a dropped row. |
| test-only: `std::thread parked` with its `std::promise<void>` / `std::shared_future<void>` gate | `std::thread` blocked on a gate inside the fake commit | the Catch2 test frame of "set_dex_score_policy: a second writer in this process is told to retry" (`tests/unit/server/test_mcp_tools_dex.cpp`, `std::thread parked` in the `while_first_is_parked` lambda, its guard at the next statement) | that one test case; one thread per section run, never two at once | Acquired when the thread starts. Released by a `yuzu::test::ScopeExit` guard declared right after it, whose body sets the gate (a second `set_value` throws, so it is swallowed) and then joins; the guard runs on EVERY exit from the scope, a failing `REQUIRE`, `FAIL`, a throwing `json::parse` or any exception thrown by the body included (the second section throws on purpose and catches it outside the scope), so a joinable thread is never destroyed (`std::terminate`) and a thread parked on an unreleased gate is never joined (a hang). The wait for the thread to reach its commit is bounded at 30 s. The thread touches only its own deps and a local sink plus the shared provider and the read-only stored text; the main thread reads `first` only after the guard's scope has closed (the join is the publication). |

## Table 2 — pre-existing resources this diff touches without changing ownership

| Resource | Owner | This diff's interaction |
|---|---|---|
| `DexScorePolicyProvider` writer lock | provider | Taken inside `apply_dex_score_policy` exactly as for REST; the MCP path adds no second lock and no lock order. |
| approval ticket | `ApprovalManager` | `reset_dex_score_policy` is registered as `Infrastructure:Delete`; the existing generic gate mints and consumes the ticket before the handler runs. No new acquisition; a post-consumption failure spends the ticket by design, documented in the tool description. |
| the dispatcher's generic audit closure (`mcp.<tool>` rows) | `McpServer` (`ToolCallContext::audit`, which re-resolves the caller's principal per row) | Each of the three tools writes exactly one `mcp.<tool>` row through it, in the unchanged shape. Unlike the `dex.score_policy.*` domain rows, which this diff binds to the session resolved once per write, the generic row is resolved per row by the dispatcher (mcp_server.cpp). That is an accepted residual, stated in the `mcp_tools_dex.cpp` header and the ADR-1005 twins entry: this diff writes through the closure without changing its ownership or behaviour. |

## Tests

Test code adds Catch2 locals (an in-memory `std::optional<std::string>` store, `std::vector` audit
logs, a `McpServer` and its handler) and the one test-only thread in Table 1. No real file, process
or socket is opened. The approval round trip uses the existing `ApprovalManagerPg` bundle and skips
without a Postgres DSN.
