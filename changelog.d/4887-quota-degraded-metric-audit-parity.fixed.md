- **Result-set degraded-read paths gain a Prometheus counter and consistent audit reporting (#4306 governance follow-up).**
  `yuzu_result_set_quota_check_degraded_total` (bare, unlabeled) now increments on the async
  result-set producers' pre-dispatch quota-check-degraded refusal (REST 503 and MCP
  `kInternalError`), so a degraded Postgres read at this gate is now visible without grepping
  logs. Separately, four MCP degraded-read branches (`list_result_sets`,
  `get_result_set_members`, `get_result_set_lineage`, and the `from-inventory-query`
  parent-narrowing loop) previously discarded the audit call's return value, so a dropped
  audit row on these paths could never surface as `audit_persisted: false` in the JSON-RPC
  error envelope; they now thread it through like every other branch in this file. The three
  plain `GET /api/v1/result-sets` read routes (list/members/lineage) now also attempt to audit
  their degraded-read 503, setting `Sec-Audit-Failed` on a dropped row, matching their MCP
  twins. The post-dispatch quota-exceeded (429) message on the three async producers now
  states explicitly that a command was already dispatched and should not be re-sent, matching
  the sibling post-dispatch store-fault (500) message's posture.
