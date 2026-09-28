- **Breaking — `GET /api/v1/result-sets` can now answer `503`; the async result-set producers' post-dispatch store-fault status changed from `400` to `500` (#4306).**
  `GET /api/v1/result-sets` previously always answered `200`, even with an empty `result_sets`
  array on a degraded backend; it can now answer `503 RESULT_SET_STORE_UNAVAILABLE` on a genuine
  store read failure. Separately, the three async result-set producers (`from-tar-query`,
  `from-instruction-result`, `re-eval`) previously mapped a post-dispatch store fault to `400`;
  that is now `500 RESULT_SET_STORE_FAULT_AFTER_DISPATCH` (a server fault, not a client error,
  once a real command has already dispatched). Any caller treating the list route as
  never-erroring, or pattern-matching the old `400` on the producers' post-dispatch path, needs
  updating. See the upgrade note in `docs/user-manual/server-admin.md`.
- **Result-set async producers now fail closed on a degraded quota check or a truncated membership/list/lineage read, instead of silently proceeding as if the store were empty (#4306, #4307).**
  `ResultSetStore::count_for_owner` returned `0` on a genuine Postgres failure —
  indistinguishable from a genuinely-empty owner — so a degraded read at the
  PRE-DISPATCH per-owner quota check on the three async result-set producers
  (`from-tar-query`, `from-instruction-result`, `re-eval`) let an over-quota
  owner's dispatch fire for real before the authoritative in-transaction
  recheck (which runs *after* dispatch) ever got a chance to refuse it.
  Separately, `members`/`list_by_owner`/`lineage` returned an empty/truncated
  page on the same class of failure, indistinguishable from a genuine last
  page — including inside the `from-inventory-query` parent-narrowing loop,
  which *materialises* the (silently truncated) member set into a durable
  result set future dispatches target. Both producers, the `GET
  /api/v1/result-sets` family, and their MCP twins now refuse (503 REST /
  `kInternalError` MCP) rather than proceeding on a degraded read. The
  quota pre-check's SQL predicate is also now aligned with the authoritative
  in-transaction recheck's own predicate (expired-but-unswept rows no longer
  spuriously count against the quota), and a post-dispatch store fault while
  persisting a pending result set now maps to `500` rather than `400` — it is
  a server fault after a real command already reached agents, not a client
  error.
