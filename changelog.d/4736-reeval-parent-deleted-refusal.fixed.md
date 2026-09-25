- **Breaking — `re-eval` no longer broadcasts fleet-wide when its recorded parent set was deleted (#4306).**
  `POST /api/v1/result-sets/{id}/re-eval` and MCP `reevaluate_result_set` synthesised the
  sibling's dispatch scope from the original's *live* `parent_id` FK, which is nulled
  (`ON DELETE SET NULL`) once the parent set is deleted — turning "re-ask the same narrow
  question" into an unscoped `__all__` broadcast, the same target-erasure shape as #2500. Both
  routes now refuse (`400 RESULT_SET_BAD_REQUEST` / `kInvalidParams`, audited
  `result_set.create|denied reason=parent_gone`) when the live parent is gone but the original's
  persisted `source_payload` shows it was narrowed at creation time, instead of re-resolving that
  recorded value (which may be an alias since re-bound to a different set) or falling back to a
  broadcast. A genuinely parentless original still broadcasts on re-eval, unchanged.
