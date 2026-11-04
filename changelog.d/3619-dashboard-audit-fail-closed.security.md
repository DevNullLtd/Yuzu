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
  (`create_failed`). Every other audit row these four routes write (refusals, scope narrowing,
  outcomes) and the Echo SQL and status-scan sends keep the request's own answer but now mark the
  response `Sec-Audit-Failed: true` when the row does not persist, instead of answering exactly as
  if it had been recorded. Expect one extra audit row per console send, group creation, Echo
  re-enable and Echo purge. Not covered: `POST /api/command`, MCP `execute_instruction`,
  management-group creation through REST, MCP and Settings, and the Echo **Capture sources** push
  still audit after acting (tracked separately). Upgrade note: [`upgrading.md`](docs/user-manual/upgrading.md).
