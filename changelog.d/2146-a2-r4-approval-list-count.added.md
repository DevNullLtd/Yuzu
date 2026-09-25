- **Approval-review REST v1/MCP parity (#2146 A2-R4).** `GET /api/v1/approvals`
  and `GET /api/v1/approvals/pending/count` are new versioned twins of the
  legacy unversioned `GET /api/approvals` and `GET /api/approvals/pending/count`
  (approve/reject stay legacy-only, unchanged, in a separate follow-up); MCP
  `list_pending_approvals` is widened to the same field set
  (`reviewed_by`/`reviewed_at`/`review_comment`), and a new MCP
  `get_pending_approval_count` tool completes the twin. All three read
  surfaces share one JSON-row builder (`approval_model.hpp`) so they cannot
  drift from each other. `ApprovalManager::query()`/`pending_count()`
  previously collapsed a degraded store (not open, pool exhausted, or a
  failed query) into the same empty list / zero count a genuinely empty
  approval queue returns - a silent false-negative on exactly the signal a
  maker-checker workflow depends on. New checked twins `query_checked()`/
  `pending_count_checked()` distinguish the two, so both the REST and MCP
  surfaces now answer a genuine store failure with 503/an error envelope
  instead of a false "all clear" - a concrete `retry_after_ms` hint on a
  transient failure (e.g. pool exhaustion), `null` on a permanent one (e.g.
  schema drift, disk-full) that will not clear on retry. The underlying
  list query is hard-capped at 100 rows; a match count over the cap sets `result_truncated_by_cap`
  (pagination-nested on REST, top-level on MCP's structured output) rather
  than presenting the capped page as the complete queue.
