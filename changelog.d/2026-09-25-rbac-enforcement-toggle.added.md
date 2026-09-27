- **RBAC enforcement enable/disable toggle (A1).** RBAC enforcement can now be switched
  on or off fleet-wide via `PUT /api/v1/rbac/enforcement` and the MCP twin
  `set_rbac_enforcement` — durable, converging across every replica within ~1s. There is
  no config-file key and no Settings-page control for this (neither ever existed,
  [#388](https://github.com/Tr3kkR/Yuzu/issues/388)). On a real transition, the toggle
  refuses (`403`) unless the CALLING operator holds authority under the regime that is
  durably true right now (closing a cross-replica cache-staleness gap in the admin gate
  itself), and refuses (`409`) unless they would remain a durable administrator under the
  destination regime: enabling requires the caller's own fleet-wide `Administrator`
  grant, disabling requires the caller's own local account to hold the `admin` role —
  each refusal names the exact follow-up call to make. The guard runs inside the same
  transaction as the flag write, under the `rbac_meta` row lock; the enable direction's
  destination check additionally takes the identical `FOR UPDATE OF pr` lock the existing
  last-Administrator guard takes, so the two serialize against each other rather than
  racing (every other check in the guard is a lock-free read). Idempotent (requesting the
  current state is a no-op, evaluating neither check) and audited
  (`rbac.enforcement_changed`), with a new `yuzu_server_rbac_enforcement_enabled` gauge, a
  `yuzu_server_rbac_enforcement_toggle_total` outcome counter, and both a threshold-free
  `YuzuRbacEnforcementChanged` alert and a direction-aware `YuzuRbacEnforcementDisabled`
  warning for the security-regression direction. A bearer token minted with a restrictive
  `mcp_tier` (e.g. `readonly`) whose principal happens to be a durable administrator can no
  longer reach this route via REST with no MFA/approval gate — REST now refuses any
  non-empty `mcp_tier` outright, the same posture every other admin-only REST route
  already had.
