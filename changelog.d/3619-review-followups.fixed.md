- **Dashboard mutations check their permission again after the audit row (#3619 follow-up to
  #7081).** Console command sends (`POST /api/dashboard/execute`), Create Group from results, and
  Echo **Re-enable** and **Purge data** on the retention-paused list checked their permission once,
  before their `attempted` audit row, and that write can wait on the audit store. With RBAC off,
  the dispatch step admits any signed-in operator, so a JIT elevation that lapsed during the wait
  still went through, including the destructive Echo purge. Each route now checks its own
  permission again after the row (`Execution:Execute`, `ManagementGroup:Write`, `Execution:Execute`
  and `Infrastructure:Delete` respectively). If the grant has been withdrawn, the request is
  refused by the permission gate (normally `403`) and nothing is sent, created or purged. The audit
  log records `failure` with `permission_revoked`: as `reason=permission_revoked` for
  `command.dispatch`, `permission_revoked source=<src>` for the Echo rows, and
  `detail=permission_revoked` for `group.create_from_results`. The Echo refusals are counted as
  `yuzu_echo_source_{reenable,purge}_total{result="denied"}`. A group's `created_by` now names the
  principal as re-authenticated after the wait.
