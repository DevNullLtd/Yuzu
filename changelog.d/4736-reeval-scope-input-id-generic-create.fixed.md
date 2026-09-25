- **The #4306 re-eval target-erasure fix now also covers result sets minted via the generic
  create routes.** `POST /api/v1/result-sets` and MCP `create_result_set` accept an
  UNRESTRICTED `source_kind`/`source_payload` (no allowlist) alongside a caller-supplied
  `parent_id`, but previously never recorded the `scope_input_id` marker the #4306 fix relies
  on -- so a row minted through these generic routes was still indistinguishable at re-eval
  time from a genuinely parentless original once its parent was deleted, silently broadcasting
  to `__all__` on the same target-erasure shape as #2500/#4306. Both routes now persist
  `scope_input_id` into the stored `source_payload` whenever `parent_id` is supplied, mirroring
  the two dedicated `from-tar-query`/`from-instruction-result` producers' existing behaviour.
