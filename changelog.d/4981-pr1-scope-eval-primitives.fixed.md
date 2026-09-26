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
