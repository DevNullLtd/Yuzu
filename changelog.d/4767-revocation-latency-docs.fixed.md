- **Revocation-latency documentation corrected for HA WS-1a.** `docs/mcp-server.md` and
  `docs/auth-architecture.md` both still stated that cookie sessions are per-process and
  in-memory, and therefore revoked immediately — untrue since durable operator sessions landed
  (`AuthManager::validate_session` routes to `validate_session_durable` whenever a `SessionStore`
  is wired). Both now state the real CC6.2 bound: the 1 s durable-generation refresh, widening to
  the 30 s stale-serve ceiling while a Postgres brownout blocks refreshes. The API/MCP token
  residual is also restated as what it is — a process-local cache, so a deterministic per-replica
  window rather than a single-process race against the eviction (#4767).
