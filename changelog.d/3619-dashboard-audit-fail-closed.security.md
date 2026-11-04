- **Dashboard mutations no longer proceed without an audit record (#3619, ADR-0033 §9).**
  Every command send from the console (`POST /api/dashboard/execute`) now writes an `attempted`
  audit row before it dispatches, not only an expression-targeted send. **While the audit store is
  unavailable, console command sends are refused with 503 (`Sec-Audit-Failed: true`) and nothing is
  sent.** The same holds for creating a management group from results and for re-enabling or
  purging an Echo source: the `attempted` row is stored first, and if it cannot be the request is
  refused with 503 and nothing is created or sent. A refused request (bad input, permission,
  scope, cross-site) writes no `attempted` row. Every console send that reaches no agent now also
  writes a `command.dispatch` `failure` row, where before only an expression-targeted send did.
  Every other dashboard audit row (refusals, scope narrowing, outcomes, Echo SQL and status-scan
  sends) keeps the request's own answer but now marks the response `Sec-Audit-Failed: true` when
  the row does not persist, instead of answering exactly as if it had been recorded. Expect one
  extra audit row per console send, group creation, Echo re-enable and Echo purge.
