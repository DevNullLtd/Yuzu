- **Breaking — four dashboard mutations no longer proceed without an audit record (#3619,
  ADR-0033 §9).** Every command send from the console (`POST /api/dashboard/execute`, whatever its
  target, read-only instructions included) now writes an `attempted` audit row before it
  dispatches, not only an expression-targeted send. **While the audit store is unavailable,
  console command sends are refused with 503 (`Sec-Audit-Failed: true`) and nothing is sent.** The
  same holds for creating a management group from results and for Echo **Re-enable** and **Purge
  data** on the retention-paused list: the `attempted` row is stored first, and if it cannot be
  the request is refused with 503 and nothing is created, sent or purged. The refusal is shown on
  the console's result line and as a toast on the Create Group form and the Echo page, and the
  Echo refusal is counted as `yuzu_echo_source_{reenable,purge}_total{result="audit_unavailable"}`.
  A request refused by its own permission, same-site, targeting, visibility or input checks writes
  no `attempted` row; a console send whose scope only fails to resolve at dispatch writes
  `attempted` and then a `failure` row. Every console send that reaches no agent now writes a
  `command.dispatch` `failure` row (`reason=no_agents_reached`), where before only an
  expression-targeted send did, and a group whose creation fails writes `failure`
  (`create_failed`). Each of the four decides its own permission again after its `attempted` row
  and acts on nothing, writing `failure` (`permission_revoked`), when the grant was withdrawn
  meanwhile; Create Group also re-checks the session and visibility (`session_revoked`,
  `scope_revoked`). Every other audit row these four routes write themselves (refusals, scope
  narrowing, outcomes) and the Echo SQL and status-scan sends keep the request's own answer but
  now mark the response `Sec-Audit-Failed: true` when the row does not persist, instead of
  answering exactly as if it had been recorded. The permission-denial row
  (`auth.permission_required`) is written by the shared permission gate, not these routes, and a
  lost one still answers a plain `403`
  (tracked in #7096). Expect an `attempted` row ahead of the outcome row of every console send
  that was not expression-targeted (those already wrote one), every group creation, and every Echo
  re-enable and purge. Not covered, among others: `POST /api/command`, MCP
  `execute_instruction`, the legacy command forwarder, management-group creation through REST, MCP
  and Settings, and the Echo **Capture sources** push still audit after acting (tracked in #7073,
  #7074 and #7075); the REST twins that audit first decide their permission again after that row
  (#7110). See [Upgrading](docs/user-manual/upgrading.md).
