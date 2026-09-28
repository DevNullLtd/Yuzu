- **Every result-set create route now bounds `parent_id` to 64 bytes before it can reach a persisted `scope_input_id`, closing an unbounded-copy gap on four REST routes (#4734).**
  `scope_input_id` is written by copying the caller's raw `parent_id` string
  verbatim; the MCP result-set tools already bounded `parent_id` before that
  copy, but four REST routes did not: the generic `POST /api/v1/result-sets`
  route, `from-inventory-query`, and the shared dispatch engine behind
  `from-tar-query`/`from-instruction-result` all now reject an
  oversized `parent_id` with `400` before any lookup, dispatch, or store
  write, matching the MCP tools' existing `kResultSetParentIdMaxLen` bound.
