- **Breaking — `POST /api/policies/{id}/evaluate` and `POST /api/policies/{id}/remediate`
  (when `agent_ids` is supplied) can now answer `503` in cases that previously answered a
  false-clean `409` ("matches no agents") or a false-denial `400` (#4981 PR-1).** Automation
  polling either route that treats `409`/`400` as terminal, or that otherwise assumes these
  routes never fail on infrastructure grounds, should treat the new `503` as retryable and
  distinct from a genuine "no agents matched"/"request rejected" outcome. See the upgrade note
  in `docs/user-manual/server-admin.md`.
- **Closed a TOCTOU fail-open in `from_result_set:` scope dispatch, and made a presence-store
  outage a fail-closed abort instead of a silently-narrowed match.** `ResultSetStore::member_set_owned`
  is now a single, snapshot-consistent statement — a result set deleted (explicit delete or the
  TTL reaper) between a caller's own pre-dispatch owner-check gate and the registry's later
  membership read used to read back as a successful, empty membership, which a `NOT
  from_result_set:<id>` scope inverted into a fleet-wide match; it now aborts the dispatch instead
  (`AgentRegistry::evaluate_scope` returns `ScopeEvalError::Kind::OwnerCheckFailed`, audited as
  `owner_check_failed`). Separately, `OfflineEndpointStore::query_live_ids` now reports a genuine
  read failure or a truncated (over-cap) result as a typed error rather than an empty vector, so a
  cross-replica presence-store outage during fleet-wide scope evaluation now aborts
  (`ScopeEvalError::Kind::PresenceDegraded`) instead of silently evaluating as if no presence-only
  agents existed. `AgentRegistry::evaluate_scope_local` (a new entry point, never presence-aware)
  keeps the three local-only Guardian push/reconcile paths unaffected by presence-store health.
  `POST /api/policies/{id}/evaluate` and `POST /api/policies/{id}/remediate` (when `agent_ids` is
  supplied) now correctly return `503` for a scope-evaluation abort of either kind above, instead
  of a false-clean `409` "matches no agents" or a false-denial `400` audited as an operator
  `denied` — both routes' non-error dispositions were previously indistinguishable from a genuine
  empty-scope match.
