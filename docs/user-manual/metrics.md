# Prometheus Metrics and Observability

Yuzu exposes a Prometheus-compatible `/metrics` endpoint on the server and
provides real-time event streaming for dashboard live updates. This page covers
how to scrape metrics, what is exposed, and how to connect Grafana or other
monitoring tools.

## Metrics endpoint

### GET /metrics

Returns all server and connected-agent metrics in Prometheus exposition format.
Localhost requests (`127.0.0.1`, `::1`) are always unauthenticated for
Prometheus scraping. Remote requests require authentication by default. Use
`--metrics-no-auth` (env: `YUZU_METRICS_NO_AUTH`) to allow unauthenticated
remote access for external monitoring infrastructure.

```bash
curl -s 'http://localhost:8080/metrics'
```

**Example response (excerpt):**

```
# HELP yuzu_http_requests_total Total HTTP requests by method, status, and principal_class
# TYPE yuzu_http_requests_total counter
yuzu_http_requests_total{method="GET",status="200",principal_class="human"} 1542
yuzu_http_requests_total{method="POST",status="200",principal_class="agent"} 87
yuzu_http_requests_total{method="GET",status="404",principal_class="none"} 12
yuzu_http_requests_total{method="POST",status="200",principal_class="engine"} 34

# HELP yuzu_command_duration_seconds Command execution latency in seconds
# TYPE yuzu_command_duration_seconds histogram
yuzu_command_duration_seconds_bucket{le="0.005"} 12
yuzu_command_duration_seconds_bucket{le="0.01"} 47
yuzu_command_duration_seconds_bucket{le="0.025"} 180
yuzu_command_duration_seconds_bucket{le="0.05"} 540
yuzu_command_duration_seconds_bucket{le="0.1"} 980
yuzu_command_duration_seconds_bucket{le="0.25"} 1320
yuzu_command_duration_seconds_bucket{le="0.5"} 1480
yuzu_command_duration_seconds_bucket{le="1.0"} 1530
yuzu_command_duration_seconds_bucket{le="2.5"} 1541
yuzu_command_duration_seconds_bucket{le="5.0"} 1542
yuzu_command_duration_seconds_bucket{le="10.0"} 1542
yuzu_command_duration_seconds_bucket{le="+Inf"} 1542
yuzu_command_duration_seconds_sum 198.74
yuzu_command_duration_seconds_count 1542

# HELP yuzu_agents_connected Number of currently connected agents
# TYPE yuzu_agents_connected gauge
yuzu_agents_connected 47
```

## Naming conventions

All Yuzu metrics follow a consistent naming scheme.

| Prefix | Source | Examples |
|---|---|---|
| `yuzu_server_` | Server process | `yuzu_server_uptime_seconds`, `yuzu_server_open_connections` |
| `yuzu_server_cert_` | Certificate reload | `yuzu_server_cert_reloads_total`, `yuzu_server_cert_reload_failures_total` |
| `yuzu_agent_` | Agent process | `yuzu_agent_commands_executed_total`, `yuzu_agent_uptime_seconds` |
| `yuzu_viz_` | Fleet visualization (`/api/v1/viz/fleet/topology` + heartbeat push ingestion) | `yuzu_viz_topology_request_seconds`, `yuzu_viz_topology_pushed_total`, `yuzu_viz_topology_push_rejected_total`, `yuzu_viz_pushed_cap_evictions_total`, `yuzu_viz_pushed_map_size` |

## Internal-CA / default-certificate metrics

| Metric | Type | Description |
|---|---|---|
| `yuzu_server_default_certs_active` | gauge | `1` when the server is running with built-in per-install **default** certificates, `0` otherwise. Alert on `== 1` for any production deployment — defaults are convenience certs and should be replaced (see `security-hardening.md`). |
| `yuzu_server_ca_crl_publish_failures_total` | counter | Failed CRL (re)publish attempts, whatever the cause — e.g. the CA root read or CA key load failed, CRL build/sign failed, no database connection within 2.5 s, a wait of more than 5 s for the `ca_store.ca_crl_versions` table lock, a statement or idle-in-transaction timeout, a degraded revoked-set or number read, an insert or COMMIT failure, the CA root changing twice mid-publish, or another publish in the same process still running after 7.5 s. Every failed publish counts; the one exception is the background freshness pass finding another publish already running in the same process, which it skips (a skip is not a failure) instead of waiting. A failure of the freshness pass's unpublished-revocation *check* (not a publish) is logged at warn and not counted (#4830). Server-side revocation enforcement is unaffected; the public CRL is stale until the next successful publish, which the leader's freshness pass retries automatically. Fires `YuzuCaCrlPublishFailing` (`docs/prometheus/yuzu-alerts.yml`). |
| `yuzu_server_cert_expiry_timestamp_seconds{cert="default-ca"}` | gauge | Unix timestamp (seconds) at which the default cert set expires (the leaves are sized to the CA's `notAfter`, so `cert="default-ca"` is the binding expiry). Default certs are 10-year with **no auto-renewal**; the `yuzu-tls` alert rules (`YuzuCertificateExpiringSoon` warn @7d, `YuzuCertificateExpiryCritical` crit @1d in `docs/prometheus/yuzu-alerts.yml`) fire on `value - time() < window`. |

## Executions event-outbox metrics (HA WS-2a)

The durable `event_outbox` (ADR-2002 §5) shadows the execution-history SSE events and,
on a multi-replica deployment, is drained cross-replica so a subscriber on one server
replica sees live execution progress driven from any replica. See
`docs/executions-history-ladder.md`.

| Metric | Type | Description |
|---|---|---|
| `yuzu_exec_outbox_poll_published_total` | counter | Durable `event_outbox` rows re-published onto **this** replica's in-memory SSE bus by the ~2s cross-replica delivery poll — i.e. events that ORIGINATED on another replica and were fanned out to this replica's live subscribers. **Zero on a single-replica deployment** (the poll finds nothing foreign to deliver). Flat while idle *or* while stalled behind a long-running transaction that pins the substrate's `pg_snapshot_xmin` — the two are not distinguished today (delivery-lag observability is tracked for WS-11). |
| `yuzu_exec_outbox_reap_total` | counter | Aged-out `event_outbox` rows deleted by the clock-guarded 24h retention sweep. |
| `yuzu_exec_outbox_reap_clock_anomaly_total` | counter | Retention sweep passes DECLINED because the substrate `now()` reading was implausible (forward- or backward-skewed vs the persisted anchor) — the clock-guard refusing to delete under a mistrusted clock. A non-zero/rising value means investigate host/DB clock integrity, not retention. |
| `yuzu_exec_outbox_store_degrade_total` | counter | `event_outbox` **reap OR cross-replica poll** passes that failed outright (pool-acquire timeout / query error), distinct from a clock-anomaly decline. The two sources share one series today (a `stage` label to separate reap from poll is a follow-up); correlate with `yuzu_pg_acquire_timeout_total` / Postgres health. |

## Command outbox delivery metrics (HA WS-3 3.3)

Scheduled instruction fires enqueue a durable `pending` occurrence to
`CommandOutboxStore` (schema `command_outbox_store`) instead of dispatching
inline; a leader-gated delivery loop drains it and performs the actual wire
dispatch. See `docs/user-manual/instructions.md` "Execution semantics" and
`docs/postgres-migration-ladder.md`'s `CommandOutboxStore` row.

| Metric | Type | Description |
|---|---|---|
| `yuzu_server_command_outbox_degrade_total` | counter | Store-level operation (enqueue/claim) that failed outright against Postgres (pool-acquire timeout / query error), labeled `op`/`reason`. Distinct from the delivery loop's own degrade counter below. |
| `yuzu_server_command_outbox_delivered_total` | counter | Occurrences the delivery loop actually dispatched to at least one agent (`outcome.sent > 0`). The delivered SLI — deliberately excludes the "reached no agents" outcome below so a rise in no-agent misses cannot mask a drop here. |
| `yuzu_server_command_outbox_deliver_no_agents_total` | counter | Delivery attempted but reached zero agents right now (nothing currently in scope). Recorded and skipped — same as any other terminal outcome, **not** retried into a backlog. |
| `yuzu_server_command_outbox_deliver_denied_total` | counter | Re-authorization at send time (arming check) denied the occurrence — authority was revoked between enqueue and delivery. Permanent; the occurrence is marked failed, not retried. |
| `yuzu_server_command_outbox_deliver_retry_total` | counter | Delivery deferred with back-off because the dispatch-gate read was systemically unreadable (e.g. containment status), a transient condition — the occurrence stays `pending` and is re-driven. A sustained climb means the gate dependency, not the schedule, is unhealthy. |
| `yuzu_server_command_outbox_deliver_retry_cause_total{cause}` | counter | Additive breakdown of the retry counter above by `cause` (`containment_unreadable`\|`route_unreadable`) — added in HA WS-4 4.2b Task D. The unlabeled counter above keeps counting for either cause (existing dashboards/alerts key on it unchanged); this one separates a degraded quarantine/containment read from a degraded `GatewayRouteStore` directory read (`ConfinedDispatchOutcome::route_unreadable`, mirrors `containment_unreadable`'s "the read itself could not answer" shape) so a routing-directory-specific degradation is separately countable. See `docs/prometheus/yuzu-alerts.yml`'s `YuzuGatewayRouteUnreadable` alert. |
| `yuzu_server_command_outbox_deliver_errors_total` | counter | An unexpected exception during `deliver()` for one occurrence — the tick treats it as transient and reschedules with back-off rather than letting it starve the rest of the batch. |
| `yuzu_server_command_outbox_deliver_decode_failed_total` | counter | A pending row's opaque payload (`agent_ids`/`parameters`) could not be safely turned into a target/param set - a malformed row (failed to decode), or a structurally valid one nesting past `kMcpMaxJsonDepth` (json-dump-depth-guard fix, never parsed/dumped). Either way, marked failed (permanent), never dispatched with an empty target/param set. |
| `yuzu_server_command_outbox_deliver_decode_failed_cause_total{cause}` | counter | Additive breakdown of the counter above by `cause` (`payload_depth_exceeded`\|`payload_decode_failed`), added by the json-dump-depth-guard fix. The unlabeled counter above keeps counting for either cause unchanged; this one separates the two so an operator diagnosing via the metric alone (not just the `audit_fn` reason string) does not conflate a too-deep-to-parse payload with a genuinely malformed one. |
| `yuzu_server_command_outbox_deliver_degrade_total` | counter | The delivery loop's own Postgres reads/writes degraded — a `list_pending` read failure (deferring the whole tick) or a `mark_sent` write failure (the wire send already happened; the row stays `pending` and is re-driven, absorbed by agent-side `command_id` dedup). |
| `yuzu_server_command_outbox_audit_failed_total` | counter | The delivery loop's `command.outbox_delivered` audit row failed to persist (`AuditStore::log()` returned false). A background loop has no request to fail closed, so the dropped compliance row is surfaced here + a warn log rather than swallowed. Any non-zero value means delivery-outcome audit evidence is incomplete — alert on it. |
| `yuzu_server_command_outbox_pending` | gauge | The current `pending`-occurrence backlog (delivery queue depth). **The primary signal that scheduled dispatch has stalled** — a stuck delivery loop (leadership never acquired, a persistently degraded gate) shows flat event counters everywhere else, so this gauge growing without bound is the tell. |

Until a dedicated alert ships (tracked for WS-11), monitor this family
manually: alert on `yuzu_server_command_outbox_pending` growing without
bound, or on `yuzu_server_command_outbox_deliver_retry_total` climbing
steadily.

### Postgres reachability metrics (HA WS-8)

Each server replica runs a dedicated reachability probe (its own connection, not
the pool) that feeds `/readyz`'s gating `pg_reachable` row — see
`docs/user-manual/server-admin.md` "Health Endpoints". These metrics are that
probe's view, per replica.

| Metric | Type | Description |
|---|---|---|
| `yuzu_server_pg_reachable` | gauge | `1` when this replica's probe reaches a **writable** primary (the `/readyz` `pg_reachable` row is ok), else `0` — unreachable, stale, not yet probed, or connected to a server that refuses writes (a standby, or `default_transaction_read_only` on). Set on each `/metrics` scrape. Alert: `YuzuServerPostgresUnreachable` (`== 0` for 2m). Zero on several replicas at once points at the database or the network path to it, not the replicas. |
| `yuzu_server_pg_reachability_last_success_age_seconds` | gauge | Seconds since this replica's probe last succeeded. Healthy values stay under ~9 s (probe interval plus its deadlines; a multi-host DSN adds one 5 s connect deadline per silent host listed ahead of the one that answers, on each reconnect); `/readyz` reports `stale` past 15 s. Absent until the first success. |
| `yuzu_server_pg_reachability_probe_failures_total` | counter | Probes that failed (connect or query error or timeout) or reached a server that refuses writes. Pre-seeded at 0. A single increment is a blip and does not change readiness; `/readyz` goes not-ready after two consecutive failures, or at once on a refused-writes answer. |

### Agent presence metrics (HA WS-5 slice 1)

`OfflineEndpointStore` (schema `endpoint_state`) is the cross-replica agent
presence source `AgentRegistry::all_ids()`/`evaluate_scope()` merge into
scope-evaluation visibility (ADR-2002 §7a). See
`docs/postgres-migration-ladder.md`'s `OfflineEndpointStore` row for the v3
migration and `docs/observability-conventions.md` for the fail-soft posture
this counter covers.

| Metric | Type | Description |
|---|---|---|
| `yuzu_server_agent_presence_store_failed_total` | counter | A presence-store operation that degraded instead of succeeding, labeled `op` (`upsert`\|`query_live_ids`\|`remove_if_session`) and `reason` (`store_unavailable`\|`db_error`). All three operations are fail-soft by design (a degraded `upsert` just means this heartbeat's identity/liveness refresh didn't land, self-healing on the next heartbeat; a degraded read leaves `evaluate_scope`/`all_ids()` local-only for the cache window; a degraded delete leaves a departed agent's row to expire via the ordinary TTL filter instead of an immediate delete) — this counter exists so fail-soft does not also mean fail-invisible. A legitimate session-mismatch result from `remove_if_session` (zero rows matched `RETURNING`) is NOT counted here, only a genuine store-unavailable/query-error path. |

There is deliberately no success/rate counter and no dedicated alert rule yet
— same posture as `yuzu_server_gateway_route_desync_total` below: a
background rate worth paging on needs real fleet data once a multi-replica
deployment exists to generate any.

### Gateway routing directory metrics (HA WS-4 4.1)

`GatewayRouteStore` (schema `gateway_route_store`) is the fenced agent→cluster
routing directory written on the gateway-upstream connect/disconnect/heartbeat
paths (`register_fresh`/`announce_connected`/`deregister`/`renew_leases`). See
`docs/postgres-migration-ladder.md`'s `GatewayRouteStore` row for the full
epoch-fence design. The desync counter below was added in slice 4.2a; the
reap-outcome counter was added alongside it in the same slice's governance
fold.

| Metric | Type | Description |
|---|---|---|
| `yuzu_server_gateway_route_write_failed_total` | counter | A `GatewayRouteStore` directory write that degraded instead of succeeding, labeled `op` (`register_fresh`\|`announce_connected`\|`deregister`\|`renew_leases`\|`reclaim_tombstoned_session`) and `reason` (`store_unavailable`\|`db_error`). **Per-site posture (HA WS-4 4.2b Task B / 4.4 UP-4), not uniformly fail-open, and NOT uniform per `op` label either — `op="renew_leases"` has TWO call sites with DIFFERENT postures sharing one label:** `op="register_fresh"` is fail-**CLOSED** — the ProxyRegister RPC is refused (`UNAVAILABLE`) rather than proceeding, since that write CREATES the row and a missed create has no other writer to fill it in. HA WS-4 4.4 added two more fail-**CLOSED** sites for the same reason: ProxyRegister's replay-ADOPT decision calls `renew_leases` and (on a miss) `reclaim_tombstoned_session` to decide adopt-vs-refuse, and BOTH refuse (`UNAVAILABLE`) on a degraded read rather than gambling on an unverified ADOPT — see ADR-2002 §7c's UP-4 fix. The ORDINARY, periodic BatchHeartbeat `renew_leases` call (extending an already-converged row's lease, no adopt decision riding on it) stays fail-**OPEN** as before — a degraded batch at worst leaves rows stale, which a future reader already treats as not-routable, and refusing the whole heartbeat batch over one failure would be a much larger blast radius. `op="announce_connected"` and the ordinary (non-decision) `op="deregister"` also stay fail-**OPEN** since each only extends/tears down an already-durable row. This counter is the only signal a systemic Postgres write problem would otherwise leave invisible for the fail-open ops/sites. |
| `yuzu_server_gateway_route_desync_total` | counter | A directory OR in-memory-registry session-guard that correctly REJECTED a write/lookup because the presented session doesn't own the row/session (`op` ∈ `renew_leases`\|`announce_connected`\|`deregister`\|`notify_stream_status`\|`proxy_register`, `outcome` ∈ `shortfall`\|`session_mismatch`\|`unknown_session`\|`stale_home`\|`malformed_home_id`\|`session_superseded`\|`stale_connected_session`). Distinct from the write-failed counter above — the call succeeded, the guard just refused to touch a row/session it doesn't own. `op="proxy_register", outcome="session_superseded"` (HA WS-4 4.4, `#4246` #6) is the replay-ADOPT decision refusing a presented session outright (`FAILED_PRECONDITION`) because the directory row is LIVE under a different session — a genuine stale/zombie replay. `op="notify_stream_status", outcome="stale_connected_session"` (HA WS-4 4.4 post-build review, PR #4636) is the IN-MEMORY `AgentRegistry::set_gateway_route` guard rejecting a CONNECTED whose session, though still a live entry in `gateway_sessions_`, is no longer the CURRENTLY-installed one for this agent — distinct from `outcome="unknown_session"`, which fires when the session isn't in `gateway_sessions_` at all. A low background rate is expected (stale/superseded-session notifications); a sustained rise means the in-memory `gateway_sessions_` map and the durable directory have gone out of sync (HA WS-4 4.2a, `#4246` item #8). Deliberately excludes a benign `register_fresh` epoch-race loss. `op="renew_leases", outcome="unknown_session"` (HA WS-4 4.2b Task B) is `BatchHeartbeat` excluding a heartbeat whose session isn't locally known — nothing to correlate an `agent_id` against for the `#4246` #10 renew correlation — the SAME per-replica-in-memory limitation already tracked for the ProxyRegister known-session check (`#4246` #3, deferred to WS-5 shared presence); unreachable on today's single-replica monolith. **Two benign contributors an SRE must not page on:** (a) a post-restart/failover baseline rise — a replica that just lost its in-memory `gateway_sessions_` emits `unknown_session`/`shortfall` until agents re-announce/reap; this is the dominant post-restart symptom, not an incident by itself; (b) a redelivered/duplicate `DISCONNECTED` notification, which counts as a `deregister`/`session_mismatch` the second time it arrives. **HA WS-4 #4324** added two more outcomes on the same counter: `op="deregister", outcome="stale_home"` is the per-home stream-generation fence correctly rejecting a same-session late `DISCONNECTED` from an already-torn-down gateway home against a newer re-home — the case the fence exists to catch, not an error; `outcome="malformed_home_id"` (`op` ∈ `announce_connected`\|`deregister`) is an oversized (>64 byte) incoming `stream_home_id`, clamped to empty rather than rejecting the RPC. Both are pre-seeded to zero at boot and remain unalerted this slice, same as the other guard-rejection outcomes above. |
| `yuzu_server_gateway_route_reap_total{outcome}` | counter | `reap_stale_routes()` background-tick outcomes (HA WS-4 4.2a governance fold), `outcome` ∈ `ok`\|`ok_capped`\|`recovered`\|`declined`\|`skipped`\|`error`. `declined` means the pass was skipped by the clock-guarded-retention anomaly guard (an implausible or unparseable `now()`/persisted-anchor reading, an anomaly whose direction differs from the anchor's prior decline, or — PR #4299 round 4 — a same-direction anomaly that has not yet PERSISTED a real-time-plausible interval) and reaped nothing; `recovered` (PR #4299 round-2 review) means a clock anomaly PERSISTED a real-time-plausible interval at the SAME (anchor, direction) and this pass drained the resulting backlog under the usual caps, per the decline-once/drain-on-repeat guard — a sustained non-zero `recovered` rate is worth an operator look (a clock anomaly or a real gap), even though nothing failed; `ok_capped` (PR #4299 round 4) means a clean accepted pass hit `kReapCap` on a sweep AND a same-txn `EXISTS` probe confirmed a remaining backlog (observability only, NOT a cadence change) — a sustained `ok_capped` rate means the reaper is chronically behind; `skipped` (PR #4299 round-2 external review) means another replica already held the `gateway_route_store:reap` advisory lock this tick (`pg_try_advisory_xact_lock`, not blocking) — routine on a multi-replica deployment, never a failure; `error` means the store call itself failed (pool/query degradation). This is the compensating observable signal for the clock-guarded-retention part-1 carve-out and the decline-once/drain-on-repeat part-4 guard documented in `gateway_route_store.hpp`'s `reap_stale_routes` header — see `docs/clock-guarded-retention.md`'s `GatewayRouteStore` entry. |

There is deliberately no success/rate counter for either the write-failed or
the desync counter. Two alert rules shipped with HA WS-4 4.2b, in
`docs/prometheus/yuzu-alerts.yml`'s `yuzu-gateway` group:
`YuzuGatewayRouteWriteFailed` (rate-based on `yuzu_server_gateway_route_write_failed_total`,
`#4246` item #1's alert-rule half) and `YuzuGatewayRouteUnreadable` (on
`yuzu_server_command_outbox_deliver_retry_cause_total{cause="route_unreadable"}` —
see "Command outbox delivery metrics" above — the closest available signal
for `#4246` item #8's alert-rule half; a degraded directory *read* during
dispatch, not every guard-rejection outcome `yuzu_server_gateway_route_desync_total`
tracks). The desync counter's own guard-rejection outcomes
(`shortfall`/`session_mismatch`/`unknown_session`) remain without a dedicated
alert — they're expected at a low background rate (see the row above) and a
threshold that doesn't page on a routine post-restart baseline rise needs
real fleet data to set. Both shipped alerts use conservative/INITIAL
thresholds for the same reason (the #913 OTA-bounds lesson: alert thresholds
are the top source of external-review findings), to be tuned once fleet data
exists.

The directory read the `route_unreadable` alert covers is FALLBACK-ONLY as of
4.2b (HA WS-4 4.2b Task C, `dispatch_route_fallback.hpp`): confined dispatch
consults `GatewayRouteStore::lookup_routes` only for a target the local
`AgentRegistry` has no live session for, and it changes zero routing outcomes
on today's single-replica monolith — see `docs/adr/2002-high-availability-architecture.md`
§7's 4.2b status paragraph.

## SSO login metrics

Every SAML and OIDC login attempt — success or failure — increments its provider's login counter. Both counters carry a uniform `{result, role}` label set on every series (including error paths), so a dashboard can group by either label without hitting an unlabelled/labelled split.

| Metric | Type | Meaning |
|---|---|---|
| `yuzu_auth_saml_login_total{result, role}` | counter | SAML `/saml/acs` outcomes. `result` is `ok` or `error`. `role` is the resolved session role (`admin` / `user`) on `result="ok"`, and `role="none"` on every `result="error"` series (no session was ever created, so there is no role to attribute the failure to). |
| `yuzu_auth_oidc_login_total{result, role}` | counter | OIDC `/auth/callback` outcomes. Same `{result, role}` shape as the SAML counter above — `role="none"` on all error-path increments (IdP-returned error, missing `code`/`state`, and token-exchange/claim-validation failure). |
| `yuzu_auth_break_glass_login_total` | counter, no labels | SOC 2 CC6.6 — the armed break-glass account's password was accepted under `--auth-mode=sso-only` (the mandatory TOTP challenge still follows). Boot-seeded to 0 so the first use after a restart is visible to `increase()`. Rare by design; the shipped `YuzuBreakGlassLogin` alert pages on any increment. The evidence trail is the `auth.breakglass.armed` → `auth.breakglass.login` audit rows (`docs/user-manual/audit-log.md`). A break-glass attempt refused because the account has no MFA enrolled (`auth.breakglass.denied`) does not increment it; alert on that audit row instead. |
| `yuzu_auth_oidc_deprovisioned_denied_total` | counter, no labels | ADR-2001 §4/PR3 — the deny-at-login backstop: an OIDC login was refused, at either the primary pre-mint check or the post-mint re-check in `/auth/callback`, because the identity's linked SCIM resource resolved deprovisioned (deactivated, orphaned by a hard-deleted `scim_resources` row, or the `ScimStore` could not answer — fail-closed). **This is the TOTAL — the SUM of the two sub-counters below** (`yuzu_auth_oidc_deprovisioned_denied_genuine_total` + `yuzu_auth_oidc_deprovisioned_denied_store_unavailable_total`, #3069). A non-zero value on this series alone does not tell you which cause fired; alert on the `_genuine_total` sub-counter, not this one — a Postgres outage bumps this total without a single genuine deprovision-deny happening. See "SCIM deprovision-linkage metrics (ADR-2001, CC6.8)" below and `docs/auth-architecture.md` "SCIM ↔ OIDC identity linkage for deprovision". |
| `yuzu_auth_oidc_deprovisioned_denied_genuine_total` | counter, no labels | #3069 — the CC6.8-alertable half of the total above: an OIDC login was refused because the identity's linked SCIM resource genuinely resolved deprovisioned (deactivated, or orphaned by a hard-deleted `scim_resources` row) — `decision.scim_id` was present, i.e. the `ScimStore` was reachable and named a real resource. Operator action: confirm the deprovision was intentional (expected after an offboarding); if it recurs against the same identity, the user or their IdP session may not yet be aware of the termination — no code action needed, this is the backstop working as designed. |
| `yuzu_auth_oidc_deprovisioned_denied_store_unavailable_total` | counter, no labels | #3069 — the availability half of the total above: an OIDC login was refused **not** because of a real deprovision but because the `ScimStore` could not be reached (fail-closed) — `decision.scim_id` was absent. This is NOT a termination event; a non-zero/rising rate means `ScimStore`/Postgres is unavailable, not that anyone was deprovisioned — correlate with `yuzu_pg_acquire_wait_seconds`/`yuzu_pg_acquire_timeout_total` and Postgres health before treating any increment here as CC6.8 evidence. |
| `yuzu_auth_saml_deprovisioned_denied_total` | counter, no labels | ADR-2001 §4/PR4b — the SAML analogue of the OIDC total above: a SAML login was refused, at either the primary pre-mint check or the post-mint re-check in `POST /saml/acs`, because the identity's linked SCIM resource resolved deprovisioned (deactivated, orphaned by a hard-deleted `scim_resources` row, or the `ScimStore` could not answer — fail-closed). **This is the TOTAL — the SUM of the two sub-counters below** (`yuzu_auth_saml_deprovisioned_denied_genuine_total` + `yuzu_auth_saml_deprovisioned_denied_store_unavailable_total`, #3069). Same caveat as the OIDC total: alert on the `_genuine_total` sub-counter, not this one. See "SCIM deprovision-linkage metrics (ADR-2001, CC6.8)" below and `docs/auth-architecture.md` "SCIM ↔ SAML identity linkage". |
| `yuzu_auth_saml_deprovisioned_denied_genuine_total` | counter, no labels | #3069 — SAML analogue of `yuzu_auth_oidc_deprovisioned_denied_genuine_total`: the identity's linked SCIM resource genuinely resolved deprovisioned (`decision.scim_id` present). The CC6.8-alertable signal; operator action is identical to the OIDC counter's. |
| `yuzu_auth_saml_deprovisioned_denied_store_unavailable_total` | counter, no labels | #3069 — SAML analogue of `yuzu_auth_oidc_deprovisioned_denied_store_unavailable_total`: the login was refused because the `ScimStore` could not be reached, not because of a real deprovision (`decision.scim_id` absent). An availability signal, not a termination event — correlate with Postgres health. |
| `yuzu_saml_group_cap_truncated_total` | counter, no labels | Bumped once per SAML login (not once per dropped group value) when the assertion's `groups` attribute exceeded the 200-value cap and real group values were dropped. A non-zero rate means some SAML-asserted group-based RBAC role mappings may not be taking effect for the affected principal — check the assertion's attribute statement. OIDC has no equivalent counter: OIDC group claims are bounded by JWT/ID-token size rather than a fixed value-count cap, so the two providers hit different limits and are not expected to have parity here. |

## SCIM deprovision-linkage metrics (ADR-2001, CC6.8)

Two detective counters for the SCIM↔OIDC identity-link revoke seam — a SCIM
deprovision revokes API/MCP tokens across a slug's linked federated (SSO)
identities as well as the slug itself. Both are always-on (no feature flag)
and both pair with a dedicated audit action,
`scim.user.deprovision_role_refused_with_link` — see
`docs/auth-architecture.md` "SCIM ↔ OIDC identity linkage for deprovision"
and `docs/user-manual/scim-provisioning.md` "SCIM ↔ OIDC identity linkage"
for the full operator runbook. Six further ADR-2001 counters — the
deny-at-login backstops firing at OIDC/SAML login rather than at SCIM
deprovision time — live in "SSO login metrics" above, next to their
siblings `yuzu_auth_oidc_login_total`/`yuzu_auth_saml_login_total`:
`yuzu_auth_oidc_deprovisioned_denied_total` (§4/PR3) and
`yuzu_auth_saml_deprovisioned_denied_total` (§4/PR4b) are each the TOTAL of
a genuine-deny and a store-unavailable sub-counter
(`yuzu_auth_{oidc,saml}_deprovisioned_denied_genuine_total` /
`yuzu_auth_{oidc,saml}_deprovisioned_denied_store_unavailable_total`, #3069)
— alert on the genuine sub-counter, since a Postgres outage alone can bump
the total. Four more
(#3072, SAML D2 observability) are below, alongside their OIDC D2 sibling
`yuzu_scim_deprovision_unlinked_total` —
`yuzu_scim_saml_link_unmatched_total`,
`yuzu_scim_saml_link_ambiguous_total`,
`yuzu_scim_saml_link_lookup_failures_total` (all three login-time, `POST
/saml/acs`), and `yuzu_scim_deprovision_saml_unlinked_total`
(deprovision-time). See `docs/auth-architecture.md` "SAML D2 observability
(#3072)" for the honest split between what the login-time signals and the
deprovision-time tripwire can each attribute.

### Durable session-store metrics (HA WS-1/1a, ADR-2002 §4)

Operator sessions are durable Postgres rows (`SessionStore`), authored and
adjudicated against the DB clock (Postgres `now()`, #3715). All four families are
pre-seeded to 0 at boot so `increase()` alerting is meaningful.

| Metric | Type | Meaning |
|---|---|---|
| `yuzu_auth_session_store_degrade_total{op}` | counter | A genuine Postgres read/write failure on the durable-session auth hot path, labelled by `op` (`validate`/`create`/`touch`/`generation_refresh`/`reap`/`invalidate`/`invalidate_user`/`mark_mfa`/`elevate`). A `validate` degrade for an uncached token fails the request **closed** (401); `create`/`elevate`/`mark_mfa`/`invalidate*` fail the privileged op closed; `generation_refresh`/`touch`/`reap` are best-effort. Operational (ordinary PG contention/failover), not a security signal — correlate with `yuzu_pg_acquire_*` and the paired `spdlog` line. |
| `yuzu_auth_session_reap_total` | counter, no labels | Expired durable-session rows deleted by the ~15-minute clock-guarded retention sweep — the storage-limitation evidence artifact; belongs alongside the `Yuzu*Retention*` series on a retention dashboard. |
| `yuzu_auth_session_reap_clock_anomaly_total` | counter, no labels | The **DB-PRIMARY** clock-integrity monitor (ADR-2002 §4 mitigation (a)): a reap pass was declined because Postgres `now()` (read in-SQL — the same clock that authors `expires_at`) was implausibly ahead of/behind the persisted anchor, i.e. a backward/forward DB-primary clock step. A backward step is what would un-expire sessions / extend elevation & MFA windows toward their authored max. `YuzuSessionReapClockAnomaly` alerts on it — investigate the **database primary's** clock first. |
| `yuzu_auth_local_clock_backward_total` | counter, no labels | The **LOCAL host-clock** drift monitor (#3715): a replica's own wall clock was observed falling behind monotonic time. DISTINCT from the reap series — under DB-clock authority session adjudication no longer rides this host's wall clock, so a local wobble is a host-health signal, NOT a session-integrity one (do not conflate the two during a clock incident). Observe-only today; no dedicated alert. |
| `yuzu_auth_get_user_role_store_error_total` | counter, no labels | `AuthManager::get_user_role()` (the DB-authoritative role check behind legacy API-token authentication) hit a genuine AuthDB store error, not a plain not-found/invalid-username miss (#4020). Each occurrence floors the caller's legacy-token-authenticated request to `Role::user` via `auth_routes.cpp`'s `.value_or(Role::user)` — the only caller-visible signal that a store degradation is silently demoting requests, since the paired `spdlog::error` line is easy to miss under load. Pre-seeded to 0; no dedicated alert yet (follow-up). |

| Metric | Type | Meaning |
|---|---|---|
| `yuzu_scim_deprovision_role_refused_with_active_link_total` | counter, no labels | D1: a deprovision was refused (the slug's role is not `user`, per the #2021 provenance guard) for a slug with an active linked federated identity — that identity's tokens were deliberately **not** auto-revoked (auto-revoking on an IdP's unilateral say-so would reopen the #2021 hazard). A human must terminate the linked identity's credentials manually. |
| `yuzu_scim_deprovision_unlinked_total` | counter, no labels | D2: a deprovision resolved a principal set of one (slug only) but found a recorded OIDC login observation (`sub` or `oid` candidate) matching the slug's `externalId` — the user demonstrably authenticated via OIDC, but no link had formed to catch their tokens. Almost always a misconfigured `--oidc-scim-link-claim` (Entra left on the default `sub` is the common case), or an IdP whose `externalId` has no matching OIDC claim at all. A non-zero rate means some federated population's tokens are **not** being revoked by SCIM deprovision — investigate before trusting the CC6.8 claim for that population. |
| `yuzu_scim_oidc_link_write_failures_total` | counter, no labels | An OIDC login's identity-link upsert and/or login-observation write failed (a ScimStore outage during the login window). The login itself always succeeds — link/observation writes are fail-OPEN by design — so this is the only signal that identity links and D2 observations were **not** recorded for some logins. A sustained non-zero rate means links formed during the window are missing (their tokens won't be caught on deprovision) and D2's own detection is blind for those users; correlate with ScimStore/Postgres availability. |
| `yuzu_scim_saml_link_write_failures_total` | counter, no labels | A SAML login's `saml_identity_links` upsert **or** its `saml_login_observations` write failed (a ScimStore outage during the login window) — the SAML analogue of `yuzu_scim_oidc_link_write_failures_total` (ADR-2001 PR4a/#3072). The login itself always succeeds — both writes are fail-OPEN by design — so this is the signal that a SAML identity link and/or its D2 login-observation was **not** recorded for that login (the latter blinds the deprovision-time `yuzu_scim_deprovision_saml_unlinked_total` tripwire for that login). A sustained non-zero rate means SAML identities are silently not linking, so those users' sessions won't be caught on SCIM deprovision; correlate with ScimStore/Postgres availability. See `docs/user-manual/scim-provisioning.md` "SCIM ↔ SAML identity linkage" for the operator runbook. |
| `yuzu_scim_saml_link_unmatched_total` | counter, no labels | ADR-2001 #3072, login-time: a SAML login presented a linkable (stable-Format) NameID for which **zero** active SCIM resources matched it as an `externalId`. This is **drift**, not a store fault — the identity authenticated but no SCIM resource claims that `externalId` (no such SCIM user, or the IdP/SCIM `externalId` values have diverged). Pairs with the `auth.saml.link_unmatched` audit row (`reason=no_active_external_id_match`). Observe-and-proceed: the login is never denied by this signal. |
| `yuzu_scim_saml_link_ambiguous_total` | counter, no labels | ADR-2001 #3072, login-time: the same lookup as the row above, but **more than one** active SCIM resource matched the NameID as an `externalId` (the ADR-2001 §2 mis-link guard — an ambiguous match is never resolved arbitrarily). Kept in its own series rather than folded into `yuzu_scim_saml_link_unmatched_total` because a duplicate/stale `externalId` is a more actionable, distinct misconfiguration than ordinary drift. Pairs with `auth.saml.link_unmatched` (`reason=ambiguous_active_external_id_match`). Observe-and-proceed. |
| `yuzu_scim_saml_link_lookup_failures_total` | counter, no labels | ADR-2001 #3072, login-time: a SAML login with a linkable NameID for which the `ScimStore` active-`externalId` lookup itself could not answer (store outage, lease timeout, failed statement) — distinct from `yuzu_scim_saml_link_unmatched_total`'s genuine zero-match answer. A sustained non-zero rate means SAML link formation cannot even be *attempted*, not merely that it is failing to match. Pairs with the `auth.saml.link_lookup_failed` audit row. Observe-and-proceed. |
| `yuzu_scim_deprovision_saml_unlinked_total` | counter, no labels | ADR-2001 #3072, deprovision-time: the SAML analogue of `yuzu_scim_deprovision_unlinked_total` above — a deprovision resolved **zero** linked SAML identities (`saml_identity_links`, queried specifically — never the OIDC link table) for a slug, but a recorded `saml_login_observations` row shows a NameID matching that slug's `externalId`. The user demonstrably attempted a SAML login under that identity, but no link ever formed — most often an unstable-Format (`transient`/`unspecified`) NameID whose *value* nonetheless matches. **Does not** catch a stable-Format NameID that never matched any `externalId` at all — that case is caught at login time instead (`yuzu_scim_saml_link_unmatched_total`), not here; see `docs/auth-architecture.md` "SAML D2 observability (#3072)" "Honest scope" for why deprovision-time attribution of that case is deferred (issue #3098). |

## DEX live-read metrics

The synchronous live-read endpoint (`POST /api/v1/dex/devices/{id}/live`) is bounded by a server-wide concurrency cap; these metrics surface its saturation and outcomes.

| Metric | Type | Meaning |
|---|---|---|
| `yuzu_server_live_requests_total{kind, outcome}` | counter | Live-read requests by `kind` (`uptime` / `processes` / `unknown`) and terminal HTTP `outcome` (`200` / `400` / `403` / `429` / `500` / `502` / `503` / `504`). A rising `outcome="429"` rate means the concurrency cap is shedding load. |
| `yuzu_server_live_inflight` | gauge | Current in-flight synchronous live-read polls. Approaching the cap (default 4) indicates saturation; sustained at the cap alongside 429s means the live surface is a bottleneck. |

## Engine-principal revalidation-cache metrics

Every held-open SSE stream re-validates its credential on each ~3 s pump tick. For a stream authenticated by an **engine** principal that check consults `EnginePrincipalStore`, and these metrics show whether it is being served from the short-TTL liveness cache (#2367) or reaching Postgres. The cache exists to keep that per-tick load off the connection pool, where it was previously self-amplifying under a pool brownout.

| Metric | Type | Meaning |
|---|---|---|
| `yuzu_server_engine_revalidate_cache_hits_total` | counter | Liveness re-checks answered from cache — no Postgres read. In steady state hits should dominate misses by roughly `TTL / tick`. |
| `yuzu_server_engine_revalidate_cache_misses_total` | counter | Re-checks that read through to Postgres (cold, expired, or invalidated by a revoke). A rate approaching one per stream per tick means the cache is not doing its job — look for a revoke loop or a clock problem. |
| `yuzu_server_engine_revalidate_cache_size` | gauge | Principals with a live (unexpired) entry. Bounded by construction; sustained residence at the ceiling means engine-principal churn worth investigating. |
| `yuzu_server_engine_revalidate_backoff_suppressed_total` | counter | Re-checks answered `StoreUnreachable` from the failure backoff **without** taking a pool lease. **This is the brownout signal**: it only moves while the store is unreachable, and while it moves the per-tick retry amplifier is being held off. Any movement means the store is unreachable — see the `YuzuMcpEngineRevalidateStoreUnreachable` alert and `docs/ops-runbooks/engine-principal-store-recovery.md`. Read it alongside `yuzu_pg_acquire_wait_seconds` and `yuzu_mcp_stream_closes_total{reason="auth_unavailable"}` — streams are riding their grace windows and some will end. **Backoff arms only on CONFIRMED unreachability** (the store closed, a query actually ran and failed, or a lease-acquire timeout occurred with PgPool's connect-failure breaker already open) — a bare pool-lease-acquire timeout with the breaker still closed under a healthy database does not arm it, so this counter does not climb on ordinary load contention (#2456). |
| `yuzu_server_engine_revalidate_generation_capacity_fallback_total` | counter | The per-principal poisoning-guard map (#2454) was full (even after a TTL sweep) and a NEW principal's invalidate fell back to the coarse global epoch instead of getting its own slot. **Not a narrowly-scoped degradation**: while tripped, the epoch bump defeats EVERY principal's concurrent cache-write, not just the triggering one — reproducing the fleet-wide cache disablement #2454 exists to fix, bounded to start past the 1024-distinct-principals-per-63s ceiling. Since #3385 this is self-clearing: entries age out on a TTL, so the fallback stops once churn drops back under the ceiling — no restart required. Not expected under ordinary load; a climbing value means the guard is running at reduced precision — see `docs/ops-runbooks/engine-principal-store-recovery.md`. |

This cache covers only the ENGINE half of stream re-validation; the API-token half has its own (`yuzu_server_token_cache_*`).

## MCP transport metrics

Request-body rejections at the `/mcp/` ingress (#2437). The label set is
CLOSED and pre-seeded at boot, so `absent()` alerting stays meaningful.

| Metric | Type | Description |
|---|---|---|
| `yuzu_mcp_body_too_large_total{reason}` | counter | `/mcp/v1/` requests rejected at the transport before the body was read (#2437). `reason=over_cap` is a declared `Content-Length` above 4 MiB (`413`); `reason=unmeasurable` is a body this server will not admit because it cannot size it **by framing** in advance — any `Transfer-Encoding`, or a POST/PUT/PATCH with no `Content-Length` (`411`). **Does NOT cover a non-`identity` `Content-Encoding`** (D4 hardening, #2407) — httplib decompresses before its size check, but that rejection is now a `415` handled by the GENERAL pre-routing gate (every route, not just `/mcp/`) and counted by `yuzu_body_cap_rejected_total{path_class="mcp",reason="unsupported_encoding"}` below **and**, so the #2437 alert keeps an arm for it, by this counter's own `reason=unsupported_encoding` series. A `/mcp/` compressed-body rejection therefore increments both, deliberately: the general counter is the fleet-wide view and this one is the MCP-specific series `docs/prometheus/yuzu-alerts.yml` already pages on. Note the status is `415`, not the `411` the `unmeasurable` reason carries. Pre-auth, so there is no principal and no audit row: the throttled `[#2407]` warn in the journal carries the sanitized method/path/source address — that tag, not the `[#2437]` the #2437 implementation emitted, since the general gate now owns every rejection on this path. |

## Pre-auth body-cap metrics (#2407)

Request-body rejections at the general pre-routing chokepoint, **every route and every method — including `GET`/`HEAD`** (D2 hardening, #2407: the earlier GET/HEAD exclusion was removed because it was factually wrong — a GET declaring a `Content-Length` still buffers a body regardless of method) — not just `/mcp/`, which keeps emitting the metric above too, for compatibility. Since the body-cap-post-read stage (#2407), the SAME metric also carries rejections from a second, later chokepoint — see `reason=over_cap_post_read` below. Seeded per table entry at boot from `body_cap_policy.hpp`'s `kBodyCapTable`, so the label set is CLOSED and `absent()` alerting stays meaningful.

| Metric | Type | Description |
|---|---|---|
| `yuzu_body_cap_rejected_total{path_class,reason}` | counter | A request rejected because it failed the resolved route class's cap policy (#2407), from one of TWO chokepoints in `server.cpp` — see `docs/user-manual/rest-api.md` "Pre-Auth Request Body Caps" for both. `path_class` is always one of `body_cap_policy.hpp`'s fixed table labels (e.g. `mcp`, `bundles`, `scim`, `default`) — **never the raw request path**, which is attacker-controlled and would be an unbounded-cardinality label on a pre-auth metric. The first three reasons fire from the pre-routing chokepoint, **before the body is read**: `reason=over_cap` is a declared `Content-Length` above the class's cap (`413`); `reason=unmeasurable` is a chunked/undeclared body refused outright for a class whose policy entry sets `requires_measurable` (`411`) — `mcp`, `upload_session`, and `hardware` set that bit today, so `reason="unmeasurable"` is seeded only for those three `path_class` values and is not yet reachable for any other class; `reason=unsupported_encoding` (D4 hardening) is a `Content-Encoding` other than `identity` (`415`) — refused UNCONDITIONALLY on every class regardless of `requires_measurable`, so unlike `unmeasurable` this reason IS seeded, and reachable, for every `path_class` in the table. `reason=over_cap_post_read` (body-cap-post-read-stage, #2407) is different in kind, not just timing: it fires from the SECOND chokepoint, `server.cpp`'s `set_pre_request_handler`, which runs **after** httplib's `read_content` has already consumed the body into `req.body` and after the route matched, but before the route's own handler. It is the backstop for a body the pre-routing stage could not size in advance (chunked/undeclared framing on a class that does not set `requires_measurable` — 26 of the table's 29 rows) and that, once fully read, turns out to be over the class's cap (`413`). Unlike `unmeasurable`, it is NOT gated on `requires_measurable` — it is pre-seeded, at 0, for EVERY class, same as `unsupported_encoding`. It is mutually exclusive with the three pre-routing reasons **per request**, never additive: httplib's `routing()` returns as soon as the pre-routing handler answers Handled, so a request that already tripped a pre-routing reason (e.g. a measurable `over_cap`) never reaches this stage — a rise in one is never explained by a rise in the other. Two things it does **not** cover: it never fires for a `multipart/form-data` request on ANY class — httplib only appends bytes to `req.body` on the non-multipart branch, so `req.body.size()` reads 0 for every multipart request regardless of the real bytes read off the wire, and the unmeasurable-body gap is unchanged for all of them; and it never fires on an unmatched route (a 404) — `set_pre_request_handler` is invoked from httplib's `dispatch_request`, which only runs once a route has matched, so this is a narrower backstop behind the pre-routing gate, not a second universal one. `resolve_body_cap` also defines a fail-closed sentinel label, `path_class="unmatched"`, returned if `kBodyCapTable`'s always-matching catch-all entry were ever removed or mis-scoped so no row matches. It is deliberately **not** pre-seeded by the boot-time loop that seeds every real table row to 0 — a `static_assert` in `body_cap_policy.hpp` requires the table to carry a `{kBodyCapAnyMethod, ""}` catch-all row, so `best` in `resolve_body_cap` can never be null and this sentinel can never be returned: it is unreachable **by construction**, not merely on the shipped table, and there is no gap to pre-seed against. Pre-auth, so there is no principal and no audit row: the throttled `[#2407]` warn in the journal carries the sanitized method/path/source address for the three pre-routing reasons; the post-read reason's throttled warn carries the same fields under an `[#2407 post-read]` tag instead. See `docs/user-manual/rest-api.md` "Pre-Auth Request Body Caps" for the per-class cap table. |
## MCP input-bounds metrics

Argument rejections on the MCP surface (#2405, #2437). Label sets are CLOSED
and pre-seeded at boot, so `absent()` alerting stays meaningful.

| Metric | Type | Description |
|---|---|---|
| `yuzu_mcp_tool_args_invalid_total{tool}` | counter | Calls denied by the C8 pre-approval schema gate: arguments did not match the tool's served `inputSchema`, checked before an approval ticket is minted or consumed (#2405). `tool` is bounded to the approval-gated set. |
| `yuzu_mcp_tool_args_too_large_total{tool,reason}` | counter | Calls denied by a handler-side input bound, on every tier including operator. Two `tool` populations share this series: `execute_instruction` (#2437), whose `reason` is a closed per-field set (`ident_len`, `scope_len`, `scope_type`, `scope_empty`, `param_count`, `param_key_len`, `param_value_len`, `agent_ids_count`, `agent_id_len`, `agent_id_type`, `agent_ids_type`, `agent_ids_empty`, `ident_empty`, `target_conflict`); and the 19 `kFieldBoundTools` (#4353 follow-up - `create_management_group`, `update_management_group`, `add_management_group_member`, `get_management_group`, `list_management_group_roles`, `assign_management_group_role`, `check_permission`, `list_result_sets`, `create_result_set`, `create_result_set_from_inventory_query`, `create_result_set_from_tar_query`, `create_result_set_from_instruction_result`, `get_result_set`, `get_result_set_members`, `get_result_set_lineage`, `pin_result_set`, `unpin_result_set`, `reevaluate_result_set`, `delete_result_set`; `unlock_account` is the one #4353 tool that needed no handler-side twin, see mcp-server.md), whose `reason` is always the single literal `arg_too_large` - the offending field and its bound are named in the audit `detail` and the client error message instead, since no alerting need justifies a per-field breakdown for these lower-traffic tools. The paired audit row is `mcp.<tool>|denied` with detail `input bound exceeded: <reason or field message> correlation_id=<cid>`, carrying the same correlation id as the client's error envelope. |
| `yuzu_mcp_approval_refused_total{tool}` | counter | MCP approval-ticket recalls refused at the **ticket-lookup** step (#2786) or the **consume** step (#2442) — a replay of a spent ticket, a ticket minted on a surface other than MCP, a ticket recalled by a principal other than its submitter, or an approval-store failure at either step. Pre-seeded for every approval-gated tool, so `absent()` stays meaningful. A store failure is already exposed to the caller through the A4 retry envelope (`-32603` vs `-32003`); what stays withheld is the split **within** a `-32003` consume denial — a cross-surface or cross-submitter refusal is made indistinguishable from an ordinary replay so the recall cannot be used to probe which surface minted a ticket or who it belongs to — so this counter deliberately carries **no `reason` label**, and `/metrics` is not a stronger reader than the caller — it is exempt for localhost and otherwise needs only a resolved session. Publishing the kind here would hand it back to the same principal. The kind is recorded server-side only, in the paired audit row `mcp.<tool>\|denied` with detail `approval_id=<id> refused: <precondition\|not_consumable\|store_error\|foreign_origin\|foreign_submitter>` — a lookup-step store failure appends ` (lookup)`, and a consume-step failure at the #2442 origin+submitter binding check appends ` (origin/submitter unverified)`, to distinguish the site. A `kPrecondition` denial (#2443) additionally appends `: <specific fact> (ticket not consumed)` (e.g. `refused: precondition: rotation already confirmed; nothing to confirm (ticket not consumed)`) — the only kind that carries a specific reason in this string; the client-facing message stays generic (see `docs/mcp-server.md`). Alert on the rate; read the audit trail for the reason. |
| `yuzu_mcp_approval_masked_denials_total{tool}` | counter | MCP approval-ticket recalls refused by a store fault at a point where the #2442 cross-surface/cross-submitter binding check could not run — the lookup step, or the consume step's own binding-check read (#2786 arm 1). A foreign-origin or foreign-submitter ticket is exactly as likely to be behind one of these refusals as an innocent one while the fault holds, so this counter is the signal that the forgery-detection event was not simply lost. Pre-seeded for every approval-gated tool. No `reason` label, same anti-oracle posture as `yuzu_mcp_approval_refused_total` — what this counter withholds is already withheld there. |
| `yuzu_mcp_approval_precondition_denied_total{tool}` | counter | MCP approval-ticket recalls refused specifically by a pre-consume precondition (#2443) — a subset of `yuzu_mcp_approval_refused_total`, broken out because a precondition denial is already distinguishable to the caller from the response body (unlike `not_consumable`/`foreign_origin`/`foreign_submitter`, which must stay mutually indistinguishable; `store_error` is already distinguishable by response code, `-32603` vs `-32003`). Pre-seeded only for tools that actually have a precondition wired — today just `confirm_engine_rotation` — not the full approval-gated set, since the label's reachable set is narrower than the two counters above. |
| `yuzu_mcp_approval_burned_total{tool,reason}` | counter | MCP approval-ticket recalls that SUCCESSFULLY consumed a one-time, human-approved ticket and then still failed at the tool handler (#2444 item 3) — args that passed the published `inputSchema` (`yuzu_mcp_tool_args_invalid_total` above did not fire) but failed the handler's own business/state check, plus any handler-side infra failure (e.g. a degraded store) discovered only after the ticket was already spent. Distinct from the three counters above, which all fire BEFORE a ticket is consumed; this one only fires after. Wired at one chokepoint that inspects the actual JSON-RPC response for every approval-gated tool's dispatch — not per-handler audit calls, since not every handler's business rejection routes through the generic `mcp.<tool>` audit verb. `reason` is a single literal today (`handler_reject`); pre-seeded for every approval-gated tool. Does not interact with the per-submitter 25-ticket pending cap: a ticket leaves the pending bucket at admin-approval time, before it can ever reach this class. |
| `yuzu_server_dispatch_denied_total{reason}` | counter | Dispatches refused by the shared classification/authorization chokepoint (`build_classified_command`, every surface — REST `/api/command`, the legacy `chargen`/`procfetch` forwarder, MCP, dashboard, workflow, schedules), labelled by which gate refused. `reason` is a closed set matching every `DispatchDenialReason` enumerator, pre-seeded across all six at boot (`unclassified`, `ambiguous`, `anonymous_operator`, `forbidden`, `approval_required`, `kill_switched`) via the shared `to_string(DispatchDenialReason)` helper — never a hand-duplicated label string, so this family cannot drift from the audit `reason=` detail on the routes that write one. `approval_required` (#1398) is the new value: a caller held the classified RBAC permission for the pair but the pair's compiled `ExecuteGate` (`AdminOrApproval`/`AlwaysApproval`) requires an admin caller or a redeemed approval ticket that this dispatch didn't carry. `forbidden` is the ordinary RBAC denial, checked strictly before `approval_required` — a caller failing both always reports `forbidden`, never the approval reason. `kill_switched` is an operator-thrown emergency stop, deliberately distinct from `forbidden`. `unclassified`/`ambiguous` are classification misses (unknown or multiply-declared `plugin.action`), checked first. On REST (`/api/command`, `chargen`/`procfetch`) this pairs with a `command.dispatch\|denied` audit row carrying the same `reason=` value. Governance round 2 (#3685): MCP's C8 pre-mint gate (`execute_instruction`, supervised tier only, before an approval ticket is minted) is a SECOND emitter of `unclassified`/`ambiguous` on this same series — a classify-miss there is denied locally instead of falling through to `build_classified_command`, reusing the same `DispatchDenialReason` values and `to_string()` helper rather than a new taxonomy, so this remains the one series for both emitters; it produces its own discriminated `mcp.execute_instruction\|denied` audit row (detail `reason=<reason> <plugin>:<action> correlation_id=<id>`) at deny time. **#3687 (CLOSED — was the gap this paragraph used to describe):** MCP's main-handler backstop is now a THIRD emitter, covering every `DispatchDenialReason`, not only the classify-miss pair C8 already covered. `execute_instruction`'s handler runs a pre-dispatch dry run of `classify_and_authorize_dispatch` plus the per-action kill-switch check (the same decision `build_classified_command` makes) BEFORE `dispatch_fn` is ever called; on denial it increments this counter itself (`dispatch_fn` is never reached, so there is no double count) and writes its own `mcp.execute_instruction\|denied` audit row (`reason=<reason> <plugin>:<action> correlation_id=<cid>`) — the tool's JSON-RPC response also names the reason in `error.data.reason`. Before #3687 this was the one case where the tool RESPONSE collapsed into the pre-existing `no_agents_reached` result, same as an offline agent, making this counter (and the audit row) the only per-reason signal on that path; that gap is closed — the tool response is now discriminated too. **#3893 (CLOSED):** the same C8-and-main-handler pre-dispatch dry run is generalized off a shared `dispatch_pairs_for(tool_name, args)` helper to cover `execute_bundle` and `quarantine_device` too, not only `execute_instruction` — both emitter sites, both tools, same posture. REST's `/api/command` is UNCHANGED by #3687/#3893: `build_classified_command`'s denial handling still collapses `forbidden`/`anonymous_operator`/`kill_switched` into one generic "permission denied" response message (the audit `reason=` and this counter's label remain the only discriminators there); `unclassified`/`ambiguous` still get their own distinct 400 message. |
| `yuzu_server_dispatch_target_rejected_total{route,reason}` | counter | REST dispatch calls denied because a **supplied** targeting argument named nothing (#2500) — the twin of the targeting reasons above, deliberately a separate family so `yuzu_mcp_*` never counts a call that did not touch MCP. `route` is a closed set: `command` (`POST /api/command`), `mcp` (MCP `execute_instruction`'s #3685 Destructive-targeting refusal — `destructive_untargeted` is the only reason this route ever emits on this series; every other MCP-side targeting/bound denial is counted separately on `yuzu_mcp_tool_args_too_large_total`), `dashboard` (the exec console's `POST /api/dashboard/execute` Destructive-targeting refusal — like `mcp`, `destructive_untargeted` is the only reason this route ever emits on this series), `legacy` (the legacy command-forwarding path, added with #881 carrying `reason="quarantined"`, and since #3424/#3511 also `reason="unknown_plugin"` — it has no targeting-shape check of its own), `instruction_execute` (`POST /api/instructions/{id}/execute`), `result_set_parent` (the `POST /api/v1/result-sets/from-*` producers, where `parent_id` is the targeting argument), `policy_remediate` (`POST /api/policies/{id}/remediate`, where an empty target means every non-compliant agent; it also refuses `scope` outright with `scope_unsupported`, since remediation selects targets by `agent_ids` only), and `dispatch_closure` (the shared dispatch closure's last-line-of-defence arm, reached only when a CALLER — route or background runner — names no target at all; a non-zero value there is a code defect, not a client one). `reason` is a closed set with FOUR halves, all in `dispatch_target_shape.hpp`. Two are targeting mistakes: `kTargetingShapeReasons` (`agent_ids_type`, `agent_ids_empty`, `agent_id_type`, `scope_type`, `scope_empty`, `target_conflict`) emitted by the shared shape check, and `kRouteRejectReasons` (`body_type`, `parent_id_type`, `parent_id_empty`, `closure_no_target`, `scope_unsupported`, `destructive_untargeted`) emitted by the routes and the shared dispatch closure. `kRouteRejectReasons` grew a sixth member for #3685: `destructive_untargeted` (`kReasonDestructiveUntargeted`) — unlike its five siblings, each of which has exactly one owning route, this one is emitted by FIVE route labels sharing one pure function (`evaluate_destructive_targeting`): REST's `/api/command` Destructive arm, MCP's `execute_instruction` (both the C8 pre-mint gate and the main-handler backstop), the dashboard exec console's `POST /api/dashboard/execute`, and — since Wave 7 PR7.2b — `POST /api/instructions/{id}/execute` and the whole-request `/api/workflows/{id}/execute` preflight. It fires when a Destructive-classified `plugin.action` pair (17 rows today) is dispatched without explicit, non-empty `agent_ids`, and is seeded at boot on `route={command,mcp,dashboard,instruction_execute,workflow}` — all five surfaces that now share `evaluate_destructive_targeting` (Wave 7 PR7.2b closed the `instruction_execute`/`workflow` gap this doc used to track as a follow-up). `kRouteRejectReasons` grew a SEVENTH member for #2557: `destructive_no_visible_target` (`kReasonDestructiveNoVisibleTarget`), REST-only (seeded on `route=command` alone) — the confinement-side sibling of `destructive_untargeted`: explicit, non-empty `agent_ids` WAS supplied, but confining it to the caller's visible agents left none reachable (the route answers `404`, not `400`, for this reason). Before #2557 this REST arm emitted no metric at all and no audit row; the dashboard's own confinement-side refusal has always been audited under a differently-named reason (`scope_violation`, see below) but was also never counted on this series — that half of the drift is unchanged by #2557 and remains a follow-up. Note the dashboard route emits this series for the **untargeted** refusal only: its sibling refusal, when confinement against the operator's visible agents leaves no reachable target, is audited (`reason=scope_violation`) but deliberately not counted here — REST no longer matches this posture as of #2557 (REST counts and audits its own confinement-side refusal now). Seeding is **per route, not the cross-product** — the dispatch routes can emit the five targeting reasons plus `body_type`; `result_set_parent` can emit only the two `parent_id_*` ones. Seeding the full product would publish series no code path can reach, which reads on a dashboard as "never happened" when the truth is "cannot happen". The paired audit row is `command.dispatch\|denied` (detail `reason=<reason> <plugin>:<action>`, both caller-supplied fields sanitised and capped at 128 bytes), `instruction.execute\|denied` (detail `reason=<reason>`) or `result_set.create\|denied` (detail `reason=<reason> source_kind=<kind>`); MCP's `route="mcp"` twin is audited under its own per-tool verb, `mcp.execute_instruction\|denied` — the established, pre-existing convention every MCP tool call already follows (`mcp.<tool_name>`), not a new or inconsistent shape. Its `detail` string carries a `reason=` prefix at both gate sites (`reason=destructive_untargeted <plugin>:<action>`) — Gate 8 round 3 added it at the C8 pre-mint site to match C8's own `ClassifyMiss` denials on `yuzu_server_dispatch_denied_total{reason}`; the main-handler backstop's equivalent detail omitted it until governance Gate 4 consistency-auditor caught the drift (Wave 7 PR7.2b), which brought the two in line. The third is `quarantined` (`kReasonQuarantined`, deliberately in NEITHER array — it is not a targeting mistake, it is the #881 containment gate withholding a device the caller named correctly), which is why the `YuzuDispatchTargetRejected` alert excludes it. The fourth, since #3424/#3511, is `unknown_plugin` (`kReasonUnknownPlugin`, also in neither array, same reasoning as `quarantined`): the caller named a real, reachable device, but the dispatched plugin is absent from that device's own reported inventory — `dispatch_confined_arms` withholds the send rather than let it fail on the agent. Seeded on the same three routes as `quarantined` (`dispatch_closure`/`command`/`legacy`), incremented via an `audit_unknown_plugin_dispatch` helper with its own `spdlog::warn` — and, **since the PR #3939 review round, a paired audit row** (`command.dispatch_withheld`, see `audit-log.md`), correcting this doc's own earlier claim that plugin absence had "nothing for an auditor to review": a command not delivered is durable evidence regardless of whether a human decided it, per `docs/observability-conventions.md`'s MUST clause. `YuzuDispatchTargetRejected`'s expression is `reason!~"quarantined\|unknown_plugin"` — both withholding reasons are excluded, the same "one malformed broadcast against a misspelled plugin name pages ops" false-positive shape the `quarantined` exclusion already avoided, pinned by promtool CASE 61b/62b. (This metric's label is `unknown_plugin`; the API-facing `reason`/`status` value on the 503 body and MCP payload is the more caller-legible `plugin_not_found` — same underlying condition, deliberately different vocabulary for the two audiences.) `dispatch_closure` is counter-only **for the targeting reasons** — that arm lives inside a closure with no request context and is reached by background runners as well as routes, so a targeting mistake there has deliberately no audit row to correlate, and a non-zero `closure_no_target` value is a code defect. Neither statement extends to `reason="quarantined"`: that value IS audited on every route including `dispatch_closure` (as `quarantine.dispatch_denied`), and a non-zero value there means the containment gate is working, not that anything is wrong. Alert: `YuzuDispatchTargetRejected` fires when the 15-minute increase exceeds 3 (`>3/15m`) — deliberately NOT `>0`, because a single malformed request would page and the rule would be silenced within a week, taking the genuine near-miss with it. The per-event evidence is the audit row, not the alert. A non-zero rate here means a client believes it is targeting specific devices and is not — before this counter existed those calls dispatched to the whole fleet and reported success. |
| `yuzu_server_dispatch_target_rejected_total{route="result_set_inventory_query",reason}` (#4496 addendum to the row above, extended by the #4496 follow-up) | counter | The `POST /api/v1/result-sets/from-inventory-query` producer and its MCP `create_result_set_from_inventory_query` twin, a route added to the closed `route` set above. `reason` is `query_truncated` (the underlying inventory read hit its row/byte cap), `poison_excluded` (a candidate record was excluded by the #2437-class JSON depth guard), or `parse_error_excluded` (a candidate record's `data_json` failed to parse as JSON at all); named `kReasonQueryTruncated`/`kReasonPoisonExcluded`/`kReasonParseErrorExcluded` in `dispatch_target_shape.hpp`, deliberately in NEITHER of the two arrays that row describes, same carve-out as `quarantined`/`unknown_plugin`. Unlike those two, this trio is NOT excluded from `YuzuDispatchTargetRejected`'s regex: a data-quality refusal on an otherwise well-formed, correctly-targeted request is exactly the near-miss that alert exists to surface, not a withholding the alert should stay silent on. Paired audit row is `result_set.create|failure`, not `|denied` (detail `reason=<reason> source_kind=inventory_query`) - see `docs/user-manual/server-admin.md`'s dispatch-target-rejected section. |
| `yuzu_server_dispatch_fanout_throw_total{route,phase}` | counter | #2557: `POST /api/command`'s audit sink (`AuditFn`) THREW rather than returning `false` — distinct from a clean decline, which `rest_audit.hpp`'s existing persist-failure path already surfaces via `Sec-Audit-Failed`/`audit_emitted:false` and does not need a separate counter for. `route` is `command` today (the only surface this wrapper wraps). `phase` is `denial` or `success` for the local `audit_fn` wrapper, matching which audit call on the route threw. The wrapper re-throws after counting, so `rest_audit.hpp`'s own `try_persist_audit` still catches it, logs a warning, and returns `false` — the response shape (`Sec-Audit-Failed`, `audit_emitted`) is unaffected by whether the sink threw or cleanly declined; this counter exists only so an operator can tell the two apart without grepping the server log. A non-zero rate means the wired `AuditFn` (ultimately `AuditStore::log`, or whatever a test/future caller binds) is throwing rather than failing cleanly — worth investigating as a potential bug in the audit sink itself, since a well-behaved `AuditStore::log` implementation should report failure via its `bool` return, not an exception. Governance round 1 (UP-1b) widened `phase` beyond the audit wrapper: `command_routes.cpp`'s shared `guarded()` helper (wrapping every post-dispatch side effect — the quarantine/unknown-plugin audit calls, the gateway forward, the dashboard toast publish, the `command.dispatched` event emission, the plugin-`thead` render) now feeds this same series too, reusing its own site-name string directly as `phase`: `audit_quarantine_dispatch_fail_closed`, `audit_quarantine_dispatch_denied_batch`, `audit_unknown_plugin_dispatch`, `forward_gateway_pending`, `publish(command-status)`, `emit_event(command.dispatched)`, `thead_for_plugin` — none of these throwing previously moved anything but a log line. All nine `phase` values (the original two plus these seven) are pre-seeded on `route=command` at boot. |
| `yuzu_cmd_send_times_pending` | gauge | #2557: current size of `AgentServiceImpl::cmd_send_times_`, the command-id-keyed map `record_send_time`/`discard_send_time` (see fix #2/#4 in `command_routes.cpp`) use to compute per-command dispatch latency. Published by `publish_send_times_gauge_locked()` on every insert and every erase, so it always reflects the map's true live size — never a periodic sample. **Alerting stance (sre, Gate 6): dashboard-only diagnostic today, no alert rule.** Sustained growth is also the expected signature of ordinary fleet churn (more commands concurrently in flight, each waiting on its agent round trip), not only of a regression (an entry the RAII guard failed to discard) — a naive threshold alert on this series would false-positive on a busy, healthy fleet. A restart is the only mitigation for a genuine leak today (the map has no independent eviction of its own); acceptable because this is a diagnostic latency map, not user data. |

## Audit-store metrics

The audit store is the SOC 2 evidence chain, so both its write path and its
retention path are scraped. The retention clock guard these describe is
documented in `docs/user-manual/audit-log.md`.

| Metric | Type | Meaning |
|---|---|---|
| `yuzu_server_audit_events_total{result}` | counter | Audit events written, bucketed by `result` (`success` / `failure` / `denied` / `other`). |
| `yuzu_server_audit_emit_failed_total` | counter | Events that failed to persist. Non-zero means audit persistence is failing. Behavioural-PII routes fail closed with `503` when it hits them, but the counter also moves for fire-and-forget background writers (agent enrolment, schedule execution) that return no status to anyone; see the `YuzuAuditPersistFailures` alert. |
| `yuzu_server_audit_clock_anomaly_skips_total` | counter | Retention passes **declined**; nothing was deleted on a declined pass, and each one adds exactly 1. Triggers: the pass would have expired every datable row; the gap since the previous pass exceeded a fixed 7 days; or the stored reading was not usable -- *ahead* of the clock, negative, present but not an integer, or unreadable. Reducing `audit_retention_days` also declines a pass by design, because it narrows the survivor horizon. Not proof of tampering: a backward NTP correction leaves a legitimate earlier reading *ahead* of now, and a dead-CMOS boot persists a *negative* one. Elapsed time cannot separate a forward jump from an outage that long - read it as "the clock moved, **or** the server was down that long". For triage --- including how to tell a stalled drain from a normal one-off decline --- see [the retention clock guard](audit-log.md#the-retention-clock-guard). The decision rule itself lives in `classify()` and `AuditStore::cleanup_once`, pinned by tests, and is deliberately not paraphrased here. |
| `yuzu_server_audit_cleanup_failed_total` | counter | Retention passes that did not fully do their job: an unreadable probe, a failed delete, a refused implausible clock, a closed store, or an exception caught at the thread boundary. **One of the seven sites fires after a SUCCESSFUL delete** (the post-delete backlog probe), so this means "retention is not fully healthy", not "nothing was deleted". |
| `yuzu_server_audit_retention_cap_reached_total` | counter | Passes that hit the per-pass delete cap, leaving a backlog. Sustained growth means expiry is outrunning the drain. This is the failure the cap itself introduces; neither counter above moves in that state. |
| `yuzu_server_audit_rows_deleted_total` | counter | Rows deleted by retention. Read alongside the cap counter to tell a draining backlog from a stuck one. |
| `yuzu_server_audit_retention_bootstrap_declines_total` | counter | Retention passes **declined** because the pass began with no usable stored clock reading while rows were already expired (#2579). Nothing was deleted. Deliberately NOT folded into `..._clock_anomaly_skips_total`: that series' alert means "the clock moved in a way that would have wiped audit evidence", whereas this decline asserts only that nothing can yet rule that out - a weaker claim and a different incident. Expect 0 or 1 per database: the declining pass also anchors the reading, so the next pass proceeds. A value that keeps climbing means the anchor is not surviving - read it alongside `..._retention_persist_failed_total`. A SINGLE decline is deliberately unalerted - that is the ordinary schema-v3 upgrade - but a climbing value fires `YuzuAuditRetentionAnchorNotSurviving` (`increase(...[24h]) > 1`). It is deliberately not folded into `YuzuAuditRetentionClockAnomaly`, whose meaning is that the clock MOVED. See [the retention clock guard](audit-log.md#the-retention-clock-guard). |
| `yuzu_server_audit_retention_persist_failed_total` | counter | Failures to persist the retention clock reading. Sustained non-zero means clock-anomaly detection will not survive a restart. |
| `yuzu_server_audit_retention_passes_total` | counter | Retention passes **attempted**, including declined and failed ones. Alert on this NOT increasing: the other six retention counters are silence-means-healthy, so a cleanup thread that never runs leaves them flat at 0 - identical to a quiet, healthy store, while `audit.db` grows without bound. |
| `yuzu_server_audit_retention_last_pass_unixtime` | gauge | Wall-clock reading of the most recent pass; `0` if no pass has ever run on this **database** (seeded from the durable retention-meta anchor at startup, #2854 -- survives a restart, including the first PostgreSQL boot). Read WITH the counter above: stale here while that RISES means the reaper is alive but refusing an implausible clock -- a different fault from stopped. A value of `-9223372036854775808` (`INT64_MIN`) is a distinct anomaly sentinel -- the durable anchor could not be read or trusted as a plausible integer -- not a genuine timestamp; it self-corrects at the next pass whose own clock reading is plausible -- even if that pass then declines or fails for an unrelated reason -- but NOT at a pass refusing on its own implausible clock (the case above), which skips the stamp entirely. |
| `yuzu_server_audit_read_degrade_total{reason}` | counter | Audit **read** queries that could not be served and so returned `503` (deny-on-degrade — the SOC 2 evidence trail never reads as a false-empty `200`). `reason` is a closed set: `store_not_open`, `pool_acquire_timeout`, `query_error`. Any sustained non-zero value is an evidence-availability gap; see the `YuzuAuditReadDegraded` alert. |

`yuzu_server_audit_backfill_total{result}` (the one-time legacy-`audit.db` → PostgreSQL backfill
outcome) was retired along with `AuditStore::migrate_from_sqlite()` itself
(chore/retire-migrate-from-sqlite-auditstore, #3623, ADR-0009 hard-cutover Update) — the last of
19 stores to lose the metric; no production Yuzu fleet has ever run a pre-Postgres build, and the
`YuzuAuditBackfillFailing` alert retired alongside it. A leftover `audit.db` still gets a
boot-time WARN if it holds rows (`legacy_sqlite_probe::warn_if_legacy_rows`), logged, no metric.

**Alert on absence, not just on rising counters.** Most of the retention alert
rules fire on something going wrong; `..._retention_passes_total` is what catches the reaper not running at
all, which is the state in which none of the other *counter*-driven rules can fire. The `YuzuAuditRetentionNotRunning`
rule covers it. **Its companion `YuzuAuditRetentionMetricMissing` covers the one case it structurally cannot:** if this
series is absent entirely - a server predating the metric, or a scrape config dropping it - `increase()` returns an empty
vector, so `YuzuAuditRetentionNotRunning` selects nothing and can never fire. That rule keys on `absent(...)` instead, and
is fleet-wide by construction (it cannot see one server among many going quiet). The current rule set is
`docs/prometheus/yuzu-alerts.yml`.

The skips and failed counters must be alerted on separately and never collapsed:
both leave rows undeleted, so an audit table that never shrinks looks identical
either way. Only the pair distinguishes "the guard is protecting the table" from
"cleanup is broken".

## Response-store metrics

The response store (PostgreSQL schema `response_store`, ADR-0039) persists agentic
command/instruction results for the executions drawer and the `/tar` dashboard. Its
ingest is **fail-soft** (a dropped result is re-derivable operational telemetry — the
executions ladder still tracks the command), its reads are **degrade-distinguishable**
(nullopt on a store/pool failure, never a false-empty), and its TTL retention runs the
same clock-guarded sweep the audit store uses.

| Metric | Type | Meaning |
|---|---|---|
| `yuzu_server_response_ingest_dropped_total{reason}` | counter | Response result rows that did not persist, by `reason` (`store_not_open` / `pool_acquire_timeout` / `query_error` / `malformed_identity_field`). Fail-soft by design — the command is still tracked on the executions ladder — but a sustained non-zero rate means drawer/TAR result history is silently lossy. `malformed_identity_field` is a distinct case: `instruction_id`/`execution_id`/`plugin`/`agent_id` are bound unsanitized (see ADR-0039 "Ingest bounds") — a value containing an embedded NUL byte is rejected outright rather than silently truncated at the NUL, so a non-zero rate here means an agent sent a malformed identity field, not a store health problem. See `YuzuResponseMalformedIdentityDrops` (informational, not store-health) vs. `YuzuResponseIngestDrops` (excludes this reason). |
| `yuzu_server_response_read_degrade_total{reason,source}` | counter | Response reads that returned a **degrade** (nullopt, not empty), by `reason` (`store_not_open` / `pool_acquire_timeout` / `query_error` — the same three as the row above, excluding `malformed_identity_field`, which is write-path only) and `source` (`response_store`). The store seam distinguishes empty from degraded so a consumer renders a degrade banner rather than misreading a blip as "no responses". |
| `yuzu_server_response_reap_passes_total{result}` | counter | TTL reap passes, by `result`: `swept` (deleted the full expired set), `capped` (hit the per-pass row cap of 10,000 OR the delete-time budget — a backlog likely remains either way; a sustained non-zero rate means expiry is outrunning the drain on this high-write store. Since the reap chunk-cascade fix (#2691 Gate 5), the delete-time budget can be hit before any row in a chunk is actually deleted, so `capped` no longer guarantees rows were removed this pass — it guarantees a backlog probe found one), `noop` (nothing expired), `declined` (the retention classifier vetoed a would-wipe or implausible-clock pass), `declined_no_anchor` (first pass ever against a store with expired rows present — declines once, the next pass drains), `skipped_lock` (another replica held the advisory lock), `failed` (the pass errored). As with the audit reaper, alert on the total NOT increasing — a reaper that never runs leaves every result flat at 0, identical to a quiet healthy store while the table grows — **and** alert on a sustained `capped` rate. |

All reason/result dimensions are seeded to zero at boot, so absent-series alerting stays
distinguishable from a scrape failure.

## MCP progress-bridge metrics

The MCP Streamable-HTTP progress bridge projects live `notifications/progress` onto a
session's `GET` stream when `execute_instruction` is called with a `_meta.progressToken`
(see `docs/user-manual/mcp.md`). It is in-memory and bounded (256 correlation records).

| Metric | Type | Meaning |
|---|---|---|
| `yuzu_mcp_bridge_records_active` | gauge | Correlation records currently live (global cap 256). Approaching the cap means new progress requests will degrade to the plain path. |
| `yuzu_mcp_bridge_reject_total{reason}` | counter | Reservation rejections, by closed-set `reason` (`disabled` / `unknown_session` / `shutdown` / `duplicate_request_id` / `global_cap` / `pin_slots`). A rising `global_cap` rate means the bridge is at capacity. |
| `yuzu_mcp_bridge_degrade_total{reason}` | counter | `execute_instruction` progress requests that silently fell back to the plain (poll) path, by `reason`. GET-only bridge (3a): `reserve_rejected` - a reservation was rejected, with the finer reason in `reject_total`; `reserve_threw` / `no_execution_row` / `subscribe_failed` / `arm_threw` - an allocation/tracker failure. Streamed POST (3b): `bind_post_sink_failed` / `stream_install_failed` - the stream could not be established, so the call answered plain JSON or a correlated error; `arm_cancelled` - a cancel landed while arming, so the streamed intent degraded; `arm_already_armed` / `arm_not_armed` - the record was not in the state the arm expected; `post_dispatch_threw` - the command WAS dispatched and is still running, but the response could not be completed. Worth alerting on: a client got an error for work that is still going. `docs/prometheus/yuzu-alerts.yml`'s `YuzuMcpStreamedPostDispatchThrewMidStream` covers exactly this reason. Note this family means exactly what it says - a request that FELL BACK to the plain path; a failure that leaves the stream running is counted elsewhere (see `yuzu_mcp_stream_attach_audit_failures_total`). The full set is declared once as `McpStreamBridge::kDegradeReasons` and pre-seeded from it, so emit sites and seeds cannot drift. The plain response is self-sufficient (carries `execution_id`); a non-zero rate is a reliability signal, not an error. |
| `yuzu_mcp_bridge_listener_failures_total` | counter | Bus-listener copy failures contained at the noexcept boundary (the event was not latched). The durable `execution_id` fetch is the backstop. Should be ~0. |
| `yuzu_mcp_bridge_mailbox_drops_total` | counter | **RETIRED by #2412.** The bounded 16-slot arming mailbox it counted (oldest-progress frames dropped under fast-producer pressure) was replaced by a single latest-wins progress slot, so there is nothing left to drop - a superseded snapshot now counts in `yuzu_mcp_bridge_progress_suppressed_total` instead. Kept registered at zero for scrape/dashboard continuity; any nonzero value would mean a regression. |
| `yuzu_mcp_bridge_progress_suppressed_total` | counter | `notifications/progress` candidates that did NOT reach the wire, for either of two reasons that share this one counter. (1) MCP's progress-MUST-increase rule (H1): each frame must be strictly greater than the last one already committed, so a duplicate or momentarily-decreasing snapshot from the bus (fresh `refresh_counts` published on every agent response, plus snapshot-and-release publishing outside the tracker mutex) is suppressed. (2) Since #2412, the listener's single latest-wins progress slot: a snapshot the projector had not yet drained is overwritten by a newer one before it is ever seen, which also counts here. Both are CORRECT behaviour, not data loss - unlike the now-retired `yuzu_mcp_bridge_mailbox_drops_total`, which was a real drop under mailbox-cap pressure. **Movement now INCREASES with fan-out** (more concurrent progress events per record means more supersedes) - do not read a rising rate as a regression. Watch instead for a sustained high rate relative to `yuzu_mcp_bridge_projector_cycles_total` as a sign of upstream event churn; a rate that drops to zero on a session with repeatedly-refreshed progress is still worth checking (it can mean the H1 half of this counter stopped filtering, which risks a non-monotonic frame reaching a strict client). |
| `yuzu_mcp_bridge_projector_cycles_total` | counter | Projector wake cycles - an event-driven liveness signal. `yuzu_mcp_bridge_records_active > 0` with a flat rate here means the projector thread is wedged. |
| `yuzu_mcp_bridge_teardown_incomplete_total{reason}` | counter | Progress-bridge teardown steps that could not complete on the maintenance thread on a given ATTEMPT, by closed-set `reason` - it fires once per failed step per attempt, so a record retried three times moves this counter three times even though it is one strand, not three. **This is defence in depth, not the live out-of-memory signal** - all three steps are find/erase and node operations that allocate nothing, so only a mutex failure can reach them on the current code; for allocation pressure watch `yuzu_mcp_stream_terminal_publish_failures_total` instead. It exists because the day an allocating call is added to any of those steps, this becomes the signal that matters. A record whose teardown fails IS RETRIED by a later sweep (#2513), up to `Config::teardown_retry_max` retries beyond the first attempt (4 total attempts by default - `0` restores the pre-#2513 one-way RETENTION posture only; the exhausted-outcome counter/log/audit row below still fire once even at `0`); what a given attempt leaves retained depends on the reason. `unsubscribe` - the record, its streamed admission charge, and (on the pin-ack and session-death paths) its event-bus subscription, which also blocks that execution's bus channel and replay buffer from being collected; on the memory-pressure path the subscription was already removed atomically with the claim. `release_charge` - the record AND one per-session admission slot (erasing on this failure made sense only when nothing could retry; under retry the record is the only handle back to the leaked charge). `erase` - the record and one global record slot; reaching this step means the subscription and charge already settled. A retained record also pins that session's whole stream state, its replay ring and any pinned finals, past session gc. Client results remain durably fetchable by `execution_id` in every case. This counter ALONE is not yet an incident - see `yuzu_mcp_bridge_teardown_retry_total` for whether the strand recovered; the only remediation for one that did not is a process restart - see `docs/ops-runbooks/mcp-bridge-teardown-recovery.md`. |
| `yuzu_mcp_bridge_teardown_retry_total{outcome}` | counter | #2513: the final disposition of a retry pass's re-entry into a previously-incomplete teardown, by closed-set `outcome` (`recovered` \| `exhausted`). `recovered` - a fault that failed at least one prior attempt cleared and the record's teardown completed; success-shaped movement, same character as `forced_expire`. `exhausted` - the record failed every attempt up to `Config::teardown_retry_max` and is now retained exactly like the pre-#2513 one-way posture: until the process restarts. **This is the metric to alert on**, not `teardown_incomplete` alone, which moves on every attempt including ones that go on to recover. |
| `yuzu_mcp_bridge_forced_expire_total{disposition}` | counter | Parked progress-bridge records force-expired by the ring-only pressure escape hatch, by the closed-set `disposition` the visitor decided. `none` - a real final was already pinned, so the client loses nothing and the reap is pure housekeeping. `fallback_final` - a terminal DID happen but its payload is gone, so a success-shaped final pointing at `execution_id` is published in its place. Two causes, not one: the payload aged out of the bus buffer, OR it was lost to a degraded projection claim (#2528). Check `yuzu_mcp_bridge_projection_degraded_total` before treating this as a buffer-sizing signal. `synthesize_unavailable` - the bus verdict was that the execution never reached a terminal at all, so `-32014` is published. The counter is incremented at the DECISION, before the teardown publishes, so read it as the disposition that was chosen rather than as proof of delivery - a frame build or the publish ladder can still fail after it, which `yuzu_mcp_stream_terminal_publish_failures_total` and `yuzu_mcp_bridge_teardown_incomplete_total` report. A claim that loses a race with `shutdown()` and whose terminal was never independently resolved (not already published, POST-wire-delivered, or projector-settled) is reaped by shutdown and is not counted here at all - it is poisoned and evidenced separately instead, by the aggregate `mcp.bridge.shutdown_reap` audit row (#2517; no counter, since the process is exiting before any scrape). A raced claim whose terminal WAS already resolved by an independent route falls under the ordinary silent-reclaim exemption (`docs/observability-conventions.md`'s comp-S1 bullet) and is not evidenced anywhere, same as any other cleanly-resolved shutdown-time reclaim. Movement here means the cap is doing its job, and the split is the point: before it, the only forced-expire series was a FAILURE counter, so a server quietly degrading every client to the fallback and one synthesizing `-32014` looked identical on a dashboard - the distinction existed only in the `mcp.bridge.forced_expire` audit row, which nothing scrapes. Alert on a rising `synthesize_unavailable` rate (clients are being told no result exists); for a rising `fallback_final` rate, rule out the projection-degraded counter first, and only then read it as records parking for longer than the bus buffer holds their terminal, which is a sizing signal rather than a correctness one. |
| `yuzu_mcp_bridge_pressure_budget_exhausted_total` | counter | Ring-only pressure passes that stopped on their per-invocation victim budget with the cap STILL exceeded (#2489). The budget is the number of parked records the pass saw when it started. It exists because a deferred victim now advances the pass instead of ending it - without a ceiling, records parking as fast as they are expired would keep a single maintenance tick working indefinitely and delay the session GC that shares that thread. Neither an error nor a loss: the victims it did not reach are expired on the next tick. A sustained rate means arrivals are keeping pace with expiries - read it alongside `yuzu_mcp_bridge_records_active` and the streamed-POST admission rate rather than alerting on it directly. |
| `yuzu_mcp_bridge_projection_degraded_total` | counter | Progress-bridge projections that had to release their projection claim **without** the record lock, so the settle bookkeeping could not run normally (#2528). Releasing the claim is the correct trade: leaving it set wedges that record out of all four consumers, and before #2489 made a deferred victim advance the pressure pass rather than end it, one wedged record also stalled ring-only pressure relief bridge-wide. The cost is that the settle is lossy - a terminal payload that was mid-retry is not rebuilt - the degraded release path has no handle on it - so that request is answered by the success-shaped fallback final (`status:"unknown"`, fetch by `execution_id`) rather than its real result; a progress-only batch loses nothing. Like `teardown_incomplete` this needs a genuinely broken platform mutex, so **any nonzero value is a signal about the host, not a rate to tune** - the same fault reaches that counter, so read the two together. Alert on `> 0`, raw counter (the lost payload is permanent, so a self-clearing window alert would misreport it). |
| `yuzu_mcp_bridge_streaming_backstop_total` | counter | Streamed-POST records the sweep had to park because they were still in the `kStreaming` phase with a dead session, or long past the streamed-POST cap. That phase is normally left by the POST response's own releaser, so **any nonzero value means a close was swallowed or never delivered** - and no other sweep pass claims `kStreaming`, so without this backstop the record, its bus subscription, its session's whole stream state and any pinned finals would leak until the process restarts. The backstop deliberately **parks rather than reaps**: the execution may still be running and its terminal is still owed, so the record keeps its subscription and stays resumable over `GET`. Self-healing, so no restart is needed, but a sustained rate points at a releaser or connection-teardown bug worth a ticket. |
| `yuzu_mcp_bridge_charge_release_deferred_total` | counter | Streamed admission charges that could not be released at their natural release point (`arm()`'s cancel-degrade) and are therefore RETAINED on the record until its teardown reclaims them (#2529). Distinct from `teardown_incomplete`, which is the maintenance thread's own steps - this one fires on a request thread. The release is both-or-neither, so the record and the ledger still agree: a nonzero value is a DEFERRED release, never a stranded admission slot. Needs a genuinely broken platform mutex, so **any nonzero value is a signal about the host, not a rate to tune**. Alert on `> 0`. |
| `yuzu_mcp_streamed_post_enabled` | gauge | `1` if SSE-on-POST is enabled (`--mcp-enable-streamed-post`), else `0`. **Ships `1`.** The capability is complete and the four defects that gated the on-by-default flip (#2739, #2740, #2785, #2789) are fixed. Set once at boot; the same fact is logged at startup. Size shutdown grace per the Sizing bullet in `docs/user-manual/server-admin.md`, which is the one home for the formula (the cap, plus at most two pump ticks, one bounded progress drain, and its socket-write time) — that sizing is now the default posture, not conditional. If this reads `0`, the operator opted out with `--no-mcp-streamed-post`. |
| `yuzu_mcp_post_streams_active` | gauge | Streamed-POST (SSE-on-POST) responses currently held open, each pinning one HTTP worker. Bounded by the response cap (#2739, fixed) plus at most two pump ticks and one progress drain, so a long fan-out settles shortly after the cap rather than tracking the execution; streamed POST ships on by default (`--mcp-enable-streamed-post`; opt out with `--no-mcp-streamed-post`). Deliberately a **separate series** from `yuzu_mcp_streams_active` rather than a label on it: a GET channel is open-ended while a streamed POST is bounded by its response cap, so summing the two would hide which kind is saturating. Read against `yuzu_mcp_streams_cap` and `yuzu_http_held_open_responses` for headroom; sustained saturation with `post_*` rejects climbing means the streamed cap, not the pool, is the binding constraint. |
| `yuzu_mcp_stream_rejects_total{reason}` | counter | SSE denials by closed-set `reason`. GET attach: `missing_session_header` / `unknown_session` / `not_acceptable` / `per_principal_stream_cap` / `global_stream_cap` / `stream_handover_pending` / `replay_window_exceeded` / `origin`. Streamed-POST admission: `post_per_principal_cap` / `post_global_cap` (both the pre-admission `StreamBudget` check) / `post_record_cap` (`reserve()`'s own, distinct `global_record_cap` check — #2918; fixed at 256, not operator-configurable — see `yuzu_mcp_bridge_records_active` above for the leading indicator) / `post_pin_slots` / `post_duplicate_request_id` / `post_unknown_session`. Bridge-level reserve rejects are a SEPARATE family (`yuzu_mcp_bridge_reject_total`) - two families split by who refused, not by surface. **Read `post_pin_slots` together with `yuzu_mcp_bridge_pin_slots_reject_total{held}`, which says WHICH half of the admission sum held the slots - `held="pins"` is the wedge shape (only when it PERSISTS; see that row for the healthy flush window that also produces it), `held="charges"` is usually ordinary saturation but also absorbs partial wedges.** |
| `yuzu_mcp_bridge_pin_slots_reject_total{held}` | counter | Streamed admissions refused for want of a session slot, split by which half of the admission sum held them. `held="charges"` = at least one charge outstanding. `held="pins"` = finals already committed whose pins were not yet released; after the rule-(a) unpin that should not persist, so **a sustained `pins` rate is the wedged-session signature**. Since #2740 the refusal itself no longer misdescribes that case: admission first reclaims a slot from a final no wire took delivery of — an ORPHAN pin whose record a teardown erased without unpinning, else the oldest parked record's (see `yuzu_mcp_bridge_pin_displaced_for_admission_total`) — and a `pins` refusal that survives that means the reclaim found nothing to take, which happens in three states: a final still being WRITTEN by a live pump, a transient decline while one of the session's records is mid-projection, or a slot genuinely stuck (an unreleasable pin the scan could not attribute). Calls in flight are the OTHER bucket by construction - `pins` means zero charges outstanding. The first two clear on retry, so the remediation says retry first and only then suggests collecting outstanding results or re-initializing, rather than "wait for one to finish". Read *sustained* strictly: a single `pins` sample is NOT a wedge, because the charge-to-pin handover happens at terminal projection while the unpin happens only once the final reaches the wire, so every HEALTHY session passes through `pinned>0, unpinned==0` during that flush window. Its alert carries a `for` for exactly this reason, and that `for` is load-bearing rather than tuning. Note also that `charges` is **not** purely benign despite the name: it is emitted whenever ANY charge is outstanding, so a PARTIAL wedge (some pins stuck, one call genuinely live) is bucketed there, where neither this split nor its alert can see it. Measured at the admission site using the same expression admission evaluates, deliberately: an earlier version of this diagnostic was a periodic gauge over the charge ledger alone, which read zero for exactly the wedged case and non-zero for healthy concurrency. |
| `yuzu_mcp_bridge_pin_displaced_for_admission_total` | counter | A new streamed call reclaimed a session slot from an already-committed final that no wire took delivery of (#2740) - the client disconnected before its result was written, so the pin had no route left to release: a GET resume acking past it, or session death, both need a channel a POST-only client does not have. **Expected, not a fault**: it is the healthy response to disconnecting clients, and without it four such calls locked a session out of streamed POST permanently. Deliberately its own counter rather than a label on `yuzu_mcp_stream_pin_displaced_total`, which is the corroborate-before-filing signal - folding a routine event in would destroy it. Do not alert. A sustained rate has two causes worth telling apart - clients dropping before their results land, and server-side ring pressure tearing parked records down, which is separately visible as `mcp.bridge.forced_expire` - and each reclaim is also an audit row (`mcp.bridge.pin_displaced_for_admission`) naming the principal that caused it; for an ORPHAN the row's `target_id` is empty, because no record survives to name one, and the detail carries the ring event id instead. The displaced final stays fetchable by `execution_id` and stays in the ring until ordinary eviction - it loses only its eviction exemption. |
| `yuzu_mcp_bridge_pin_release_failed_total` | counter | The admission reclaim's own release of a displaced pin (#2740) THREW and was contained. The new admission is already committed at that point, so letting the throw escape would leave a session slot nothing reclaims until the arming reaper fires. Distinct from `yuzu_mcp_bridge_pin_displaced_for_admission_total`, which counts every SUCCESSFUL reclaim: this counts only a release that failed. Needs a genuinely broken platform mutex, so **any nonzero value is a signal about the host, not a rate to tune** - the same fault class as `yuzu_mcp_bridge_charge_release_deferred_total`. The admission itself stands, so the session is transiently one call OVER its cap - and correspondingly one slot tighter for future admissions - until that pin clears by another route or the next admission rejects. Alert on `> 0`. |
| `yuzu_mcp_bridge_pin_release_raced_total` | counter | The admission reclaim's release of a displaced pin (#2740) returned WITHOUT clearing the slot and without throwing - another route (a resume ack, or a final reaching the wire) got there first (#2795). The admission stands, so the session is transiently one call over its cap for the lifetime of the over-admitted call. **Client-reachable**: a client racing its own `Last-Event-ID` GET resume against a streamed POST admission on the same session reaches it, so unlike its two siblings a low steady rate is ordinary and not a host fault. Do not alert on `> 0`. It exists to make this residual RULE-OUTABLE: it previously incremented no counter at all, so an operator asking whether a full pin-slot set was real drift saw every signal flat in exactly this case. Rule it out by hand when `YuzuMcpStreamPinDisplaced` fires; the runbook has the procedure. |
| `yuzu_mcp_stream_attach_audit_failures_total` | counter | A streamed-POST attach audit the sink REJECTED (returned false rather than throwing). The stream is live and correct; what is missing is its evidence. Deliberately NOT a `bridge_degrade` reason - that family means the request fell back to the plain path, and this request did not. Unlike the GET channel there is no `Sec-Audit-Failed` header available, because installing the content provider seals the response headers, so this counter is the only signal. Any non-zero value is an audit-coverage gap (SOC 2 CC7.2). |
| `yuzu_mcp_cancel_notifications_total{outcome}` | counter | `notifications/cancelled` received, by closed-set `outcome`: `detached` (a LIVE streamed response was ended by this cancel) / `accepted` (intent recorded before the request armed, for `arm()`/`abandon()` to arbitrate) / `noop` (nothing to cancel - already finished, wrong session, or a retried cancel that already landed). The set is declared once as `McpStreamBridge::kCancelOutcomeLabels` and both the emit site and the startup seed derive from it. A high `noop` rate is a client-behaviour signal, not a server fault - clients cancelling requests that already finished, or addressing the wrong session. Not alertable on its own; useful when diagnosing a client that believes it is cancelling work. Note a cancel NEVER stops a dispatched execution - it detaches the response only (`docs/mcp-server.md`, close reasons). |
| `yuzu_mcp_maintenance_tick_failures_total{tick}` | counter | MCP maintenance ticks that threw and were contained, by closed-set `tick` (`bridge_sweep` / `session_gc`). The tick is skipped, not retried. `bridge_sweep` - pin-ack, session-death and memory-pressure teardown are all stalled while this grows, so bridge records and their pins accumulate. `session_gc` - expired sessions keep their streams and pinned finals until a tick succeeds. The two are guarded separately so a failure in one cannot suppress the other. Alert on a nonzero rate over a window, NOT on the raw counter - a skipped tick is retried next cycle, so unlike `teardown_incomplete` this condition is self-healing and its alert must clear. |
| `yuzu_mcp_stream_terminal_publish_failures_total` | counter | Terminal-frame publish failures seen by the bridge's `publish_final → fallback → poison` ladder. Non-zero means a client-visible result could not be delivered on the stream (recoverable by `execution_id`). Alert-worthy. |
| `yuzu_mcp_stream_final_unpinned_total` | counter | Committed terminal frames that found no free pin slot and were published **unpinned** (a real terminal is committed rather than lost to preserve a pin). **Structurally unreachable** while the pin array is non-empty: a full slot set now displaces its oldest pin rather than committing the *newest* final unprotected. Kept as defence in depth - a non-zero value means the array was resized to zero or the displacement path was bypassed. Alert on `> 0`. **Upgrade note:** the reading this counter used to carry ("admission accounting was violated") now belongs to `yuzu_mcp_stream_pin_displaced_total`, where since #2740 it is a signal to corroborate rather than a verdict; alert on both, and on `pin_displaced_total` rule out the two residuals (#2795, #2805) before filing drift. |
| `yuzu_mcp_stream_pin_displaced_total` | counter | An older pinned terminal yielded its eviction-exemption slot to a newer one. **A signal to corroborate, not a verdict.** The derivation lives in `McpStreamState`'s `What a FULL PIN-SLOT SET means` block (`server/core/src/mcp_stream.hpp`); the summary below is this table's own, and must be re-checked against it when the answer changes. In short: a SUCCESSFUL #2740 reclaim releases one pin and adds one charge, so the session stays AT cap and cannot cause a displacement. Only two paths can: a release that lost a race (`yuzu_mcp_bridge_pin_release_raced_total`, #2795) and a contained release throw (`yuzu_mcp_bridge_pin_release_failed_total`, #2805), each explaining one slot. The displacement is the graceful degradation, not a licence: the oldest terminal (likeliest already consumed) yields instead of the newest going unprotected, which is the wrong one to sacrifice since it is the request most likely still waiting. The displaced final becomes evictable from the replay ring, still recoverable by `execution_id`. Alert on `> 0` (the shipped `YuzuMcpStreamPinDisplaced` rule does exactly that): a SUCCESSFUL reclaim cannot cause a displacement, so this counter is not moved by ordinary traffic. Rule out the two residuals - `yuzu_mcp_bridge_pin_release_raced_total` (#2795) and `yuzu_mcp_bridge_pin_release_failed_total` (#2805) - before treating it as drift. |
| `yuzu_mcp_stream_final_credit_failed_total` | counter | A streamed-POST final was written to the wire (the client has it), but the bridge's own credit step (`on_final_written`) threw before it could run, so the session's pin is retained rather than released. The close is still reported to the client as `completed`, since that is what they received; this counter fires ONLY on a thrown failure of that step - a credit step that fails to run without throwing (for example, because the record is already gone) is a distinct failure shape this counter does not observe. Needs a genuinely broken platform mutex (the same modelled fault class as `yuzu_mcp_bridge_charge_release_deferred_total`), so **any nonzero value is a signal about the host, not a rate to tune**. Alert on `> 0`. |
| `yuzu_mcp_stream_poison_close_failures_total` | counter | A poison-path close - `poison_terminal()`'s own close, or `attach_and_replay`'s retry of a stale sink on an already-poisoned session - failed and was contained. The sticky poison flag itself is always durable regardless of this counter: every future attach still 410s. What this counts is whether the CONNECTED client was actually told - a nonzero value means some client may have kept heart-beating on a stream the server had already given up on until a later attach retried the close (poisoning is idempotent, so the retry keeps trying on every subsequent attach until one succeeds). Needs a genuinely broken platform mutex (the sink's own mutex acquisition, the same fault class as `yuzu_mcp_bridge_charge_release_deferred_total`), so **any nonzero value is a signal about the host, not a rate to tune**. Alert on `> 0` (#2531). |

All reason-label sets are closed (every value is a static literal seeded to 0 at boot),
so `absent()`/`rate()` alerting is meaningful on a healthy server.

## Pre-flight runner metrics

| Metric | Type | Meaning |
|---|---|---|
| `yuzu_preflight_tick_errors_total` | counter | Exceptions caught by the background `PreflightRunner`'s per-tick try/catch (60 s cadence). A rising rate means pre-flight runs are not being re-dispatched/settled — check the server log. |

## Webhook / offload delivery metrics (#3261, extended ADR-0057)

`WebhookStore` and `OffloadTargetStore` (see [REST API §Webhooks / §Offload Targets](rest-api.md)) dispatch deliveries through a bounded worker pool; these counters cover delivery outcomes and pool backpressure. Every no-label counter below is pre-seeded to `0` at boot, so `absent()`-based alerting stays meaningful on a fresh server before the first delivery ever fires. Neither store has a backfill metric today: `OffloadTargetStore` never had one (fresh-starts unconditionally per ADR-0009's amendment, no `migrate_from_sqlite()` to report an outcome for); `yuzu_server_webhook_backfill_total` was retired along with `WebhookStore::migrate_from_sqlite()` itself (chore/retire-migrate-from-sqlite-batch-a, #3623) — see ADR-0057's Update.

| Metric | Type | Meaning |
|---|---|---|
| `yuzu_server_webhook_delivery_success_total` | counter | Webhook deliveries that completed with a 2xx response. |
| `yuzu_server_webhook_delivery_failed_total` | counter | Webhook deliveries that failed (connection error, non-2xx, exception). |
| `yuzu_server_webhook_delivery_dropped_total` | counter | Webhook deliveries dropped because the delivery worker pool's bounded queue was full, or the store was quiescing (shutdown in progress). A rising rate under normal operation indicates a persistently slow/unreachable endpoint saturating the pool — check `GET /api/webhooks/{id}/deliveries` for the failing target. |
| `yuzu_server_webhook_delivery_secret_unavailable_total` | counter | Webhook deliveries skipped because the signing secret could not be decrypted (tamper, KEK loss, or a malformed blob) — never fired unsigned or with an empty secret. A sustained rate indicates a KEK-availability incident; cross-reference `yuzu_server_secret_decrypt_failures_total{store="webhook_store"}` for the specific failure class. |
| `yuzu_server_webhook_fire_event_degraded_total` | counter | `fire_event` ticks that skipped their enabled-webhook scan because the Postgres pool did not yield a connection within its bounded (300ms) acquire, or the enabled-webhook query failed after a connection was acquired — either way, that tick's events are not delivered to any webhook. |
| `yuzu_server_webhook_delivery_log_failed_total` | counter | Delivery-log `INSERT`s (`webhook_deliveries`) that failed against an open store — the delivery itself still ran; only its record did not persist. |
| `yuzu_server_offload_delivery_success_total` | counter | Offload-target deliveries that completed with a 2xx response. |
| `yuzu_server_offload_delivery_failed_total` | counter | Offload-target deliveries that failed (connection error, non-2xx, exception, a tampered non-http(s) URL, or a stored `auth_type` that doesn't resolve to a recognized value — a tampered/legacy row, refused rather than dispatched unauthenticated). |
| `yuzu_server_offload_delivery_dropped_total` | counter | Offload-target deliveries dropped because the delivery worker pool's bounded queue was full, or the store was quiescing. |

Two more, added with the ADR-0059 Postgres migration (also pre-seeded to `0` at boot; this store has no backfill metric — ADR-0009's fresh-start-by-default amendment means there is no legacy migration to report an outcome for):

| Metric | Type | Meaning |
|---|---|---|
| `yuzu_server_offload_delivery_credential_unavailable_total` | counter | Offload-target deliveries skipped because the target's credential (ADR-0010) failed to decrypt — the delivery is never fired unsigned. A nonzero rate points at KEK/keys-directory health, not the target's own configuration; cross-check against `yuzu_server_secret_decrypt_failures_total{store="offload_target_store"}` for the specific failure class. |
| `yuzu_server_offload_fire_event_degraded_total` | counter | `fire_event`'s enabled-target scan could not acquire a database connection within its 300ms bound, or the query itself failed — that tick's events were not delivered to any target. A rising rate under normal load indicates pool exhaustion on the hot dispatch path. |

## Patch-manager write-outcome metrics (ADR-0062)

`PatchManager` (see [REST API §Patch Management](rest-api.md)) records one outcome per write call.
Pre-seeded to `0` at boot for every `op`×`result` combination, so `absent()`-based alerting stays
meaningful before the first call ever fires.

| Metric | Type | Meaning |
|---|---|---|
| `yuzu_server_patch_manager_writes_total{op,result}` | counter | Outcome of each `PatchManager` write, `op` ∈ `{record_patches, deploy_patch, cancel_deployment}`, `result` ∈ `{success, failed, rejected_oversized}`. A `failed` result means the Postgres transaction backing that call didn't commit (pool exhaustion, a query error) — the caller sees the store's existing not-available/failure error either way; this counter is the only cross-request signal. `rejected_oversized` (currently only on `op="deploy_patch"`) increments when the request's `agent_ids` list exceeds `kMaxDeployTargets` (5000, post-de-duplication), before the write is attempted — distinct from `failed`, which means a write was attempted and the transaction didn't commit. Note: `record_patches()` has no production caller today (ADR-0062, #3676), so this series' `op="record_patches"` values stay at their pre-seeded `0` until that gap is closed. |
| `yuzu_server_workflow_engine_writes_total{op,result}` | counter | Outcome of each `WorkflowEngine` write, `op` ∈ `{create_workflow, delete_workflow, execute, cancel_execution}`, `result` ∈ `{success, failed}` (ADR-0064). `execute` increments only on a **completed run** (success/failed at the end of the step loop) — an admission failure (workflow not found, or a genuine DB failure creating the execution row) does not touch this counter, so it measures "runs that actually executed", not every call to `execute()`. `delete_workflow` increments only on a genuine DB failure or an actual delete — a `not_found` result (a bad id, or a legitimate double-delete) is caller input, not a store-health signal, and is not counted as `failed`. Note: `cancel_execution` has no REST/MCP caller today, so this series' `op="cancel_execution"` values stay at their pre-seeded `0` until a route is wired. |



The fleet-visualization REST surface (PR 3 of feat/viz-engine ladder; see [REST API §Fleet Visualization](rest-api.md)) exposes the following metrics. Routes share one `FleetTopologyStore` cache; all metrics are process-global.

| Metric | Type | Description |
|---|---|---|
| `yuzu_viz_topology_request_seconds` | histogram | End-to-end request latency on the success path (200). Default bucket boundaries above. Cache-hit p99 should be <100 ms; cache-miss p99 is bounded by the 5 s fetcher deadline + 0.5 s overhead. |
| `yuzu_viz_topology_fetch_duration_seconds` | histogram | Duration of the inner agent-dispatch path (`tar.fleet_snapshot` fan-out + response aggregation), measured only on cache-miss refills. Distinguishes "agent dispatch is slow" from "the rest of the request is slow" (auth, RBAC, response serialisation, network egress). Observed even on fetcher exception so a hung fetcher produces a visible upper-bound observation. |
| `yuzu_viz_cache_hit_total` | counter | Increments on each request that observed a TTL-fresh slot. Pair with `yuzu_viz_cache_miss_total` to compute hit rate. |
| `yuzu_viz_cache_miss_total` | counter | Increments on each request that triggered a refill. With a 60 s TTL and 1 RPS dashboard polling, expect ~1/60 of all requests. |
| `yuzu_viz_oversize_response_total` | counter | Increments on each `413` response (snapshot exceeded `machines_max`). Operator misconfiguration signal. |
| `yuzu_viz_agent_dispatch_timeout_total` | counter | Increments per agent that was dispatched `tar.fleet_snapshot` but didn't respond within the 5 s deadline. A non-zero rate signals partial fleet outage. |
| `yuzu_viz_refill_oversize_drops_total` | gauge | Refills whose serialised size exceeded `max_snapshot_bytes` (256 MiB default). The result is returned to the caller but NOT cached, so the next request re-runs the full fetcher. Non-zero indicates a misbehaving agent or an undersized cap. |
| `yuzu_viz_refill_wait_timeouts_total` | gauge | Single-flight waiters that timed out on `cv.wait_for` before the refill completed. Non-zero indicates the fetcher is exceeding its deadline. |
| `yuzu_viz_refill_waiters_total` | gauge | Number of fetch waiters that piggybacked on an in-flight refill (single-flight wins). High values indicate stampede risk on `/viz/fleet`. |
| `yuzu_viz_local_edges_dropped_total` | gauge | `EdgeScope::Local` connection edges dropped before serialisation because no reciprocal half was visible in the same agent payload. Non-zero is expected under normal churn (kernel race during socket teardown, the agent's 4096-connection cap cutting a partner); a sustained spike vs steady-state indicates systematic loss. |
| `yuzu_viz_topology_pushed_total` | counter | Agent-pushed `fleet_snapshot.v1` payloads accepted into the `FleetTopologyStore`. Labelled `via=direct\|gateway` (direct `HeartbeatRequest` vs gateway `BatchHeartbeat`); sum across the label for fleet-wide push volume. |
| `yuzu_viz_topology_push_parse_errors_total` | counter | Agent-pushed payloads rejected by the shared parser (oversized, row-cap exceeded, malformed JSON). Labelled `via=direct\|gateway`. |
| `yuzu_viz_topology_push_rejected_total` | gauge | Pushes rejected by the IP-spoof guard because a claimed `local_ip` is owned by a live agent. A non-zero rate signals a spoofing campaign or a NAT/DHCP misconfiguration. |
| `yuzu_viz_pushed_cap_evictions_total` | gauge | `pushed_` map entries evicted because the map was at `kPushedMapHardCap` (100000) when a new agent pushed. Non-zero means the fleet outgrew the cap or a cap-flood attack is evicting legitimate agents — cross-check with the `topology.push.evicted_for_cap` audit events. |
| `yuzu_viz_pushed_map_size` | gauge | Current occupancy of the `pushed_` map. Primary memory-pressure signal — alert before it approaches the 100000 hard cap. |

## Subscribe peer-binding security counters

The per-session peer-IP binding for the agent `Subscribe` RPC (#826/#1058/#1059, NAT-aware relaxation #1128) emits two paired counters. Both carry the `event="security"` SIEM-routing label and should be read together — a spike in one alone vs both together carries very different meaning.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `yuzu_grpc_subscribe_peer_mismatch_total` | counter | `event="security"`, `gateway_mode=true\|false` | A Subscribe attempt was **rejected** because its source IP did not match the IP recorded at `Register` time and no accommodation applied. `gateway_mode` reflects whether the server is running with `--gateway-mode`. The audit row `session.peer_mismatch result=denied` (see [audit-log.md](audit-log.md)) carries the forensic detail. |
| `yuzu_grpc_subscribe_peer_advisory_total` | counter | `event="security"`, `reason="mtls_identity_match"\|"trusted_nat_cidr"`, `gateway_mode=true\|false` | A Subscribe peer-IP mismatch was **tolerated** (stream established) under a NAT-aware accommodation (#1128). `reason` distinguishes the two opt-in accommodations: `mtls_identity_match` (via `--nat-trust-mtls-identity`), `trusted_nat_cidr` (both IPs in one `--trusted-nat-cidr` range). The audit row is `session.peer_mismatch result=ok outcome=advisory`. |

**Read-together interpretation.** Both counters share the `event` and `gateway_mode` labels so an analyst can join them by operator-mode dimension. A spike in `_peer_advisory_total` alone is expected multi-egress churn in NAT-relaxed deployments and is not actionable. A spike in BOTH simultaneously is the actionable signal: it can indicate a stolen-session replay landing inside a trusted range, where the legitimate agent triggers the reject and the attacker (also in-range) is admitted via advisory. The `AgentSubscribePeerAdvisoryCorrelatedSpike` alert below encodes exactly that pattern.

### Recommended alerts

```yaml
- alert: VizFleetDispatchTimeoutsRising
  expr: rate(yuzu_viz_agent_dispatch_timeout_total[5m]) > 5
  for: 5m
  annotations:
    summary: "Fleet topology fetcher is timing out per-agent (partial fleet outage)"

- alert: VizFleetSlowRequests
  expr: histogram_quantile(0.99, sum(rate(yuzu_viz_topology_request_seconds_bucket[5m])) by (le)) > 5.5
  for: 10m

- alert: VizFleetSlowAgentDispatch
  expr: histogram_quantile(0.99, sum(rate(yuzu_viz_topology_fetch_duration_seconds_bucket[5m])) by (le)) > 5.0
  for: 10m
  annotations:
    summary: "Fleet topology agent-dispatch p99 above the 5 s fetcher deadline; agents may be unresponsive"

- alert: VizFleetRefillOversizeDrops
  expr: increase(yuzu_viz_refill_oversize_drops_total[10m]) > 0
  annotations:
    summary: "FleetTopologyStore is dropping refills above 256 MiB cap; raise --max-snapshot-bytes or scope down the fleet"

- alert: VizFleetPushRejections
  expr: increase(yuzu_viz_topology_push_rejected_total[10m]) > 0
  annotations:
    summary: "Fleet-snapshot pushes rejected by the IP-spoof guard — spoofing campaign or NAT/DHCP misconfiguration"

- alert: VizFleetCapEvictions
  expr: increase(yuzu_viz_pushed_cap_evictions_total[10m]) > 0
  annotations:
    summary: "FleetTopologyStore is evicting agents at the 100000-entry hard cap — fleet outgrew the cap or a cap-flood attack is in progress"

- alert: YuzuMcpEngineRevalidateStoreUnreachable
  expr: increase(yuzu_server_engine_revalidate_backoff_suppressed_total[10m]) > 0
  labels:
    severity: warning
  annotations:
    summary: "Engine-principal liveness re-checks are being answered from the failure backoff - the principal store is unreachable and engine streams are riding their grace windows"
    description: "This counter only moves on CONFIRMED unreachability (the store closed, or a query actually ran and failed, or PgPool's own connect-failure breaker is open) - a bare pool-lease-acquire timeout under a healthy database does not arm this backoff, so firing already rules out ordinary pool saturation. First rule out real impact: a flat yuzu_mcp_stream_closes_total{reason=\"auth_unavailable\"} means the backoff is absorbing the blip and no streams have ended. Then correlate with yuzu_pg_acquire_wait_seconds and yuzu_pg_pool_in_use for genuine connection exhaustion vs. a connect-level failure. Runbook: docs/ops-runbooks/engine-principal-store-recovery.md."

- alert: VizFleetPushedMapNearCap
  expr: yuzu_viz_pushed_map_size > 80000
  for: 10m
  annotations:
    summary: "FleetTopologyStore pushed_ map above 80% of the 100000 hard cap; evictions imminent"

# Stolen-session signals (event="security" — routed to the SIEM via Prometheus;
# see observability-conventions.md). The audit rows session.peer_mismatch /
# session.identity_mismatch carry the forensic detail.
- alert: AgentSubscribePeerMismatch
  expr: increase(yuzu_grpc_subscribe_peer_mismatch_total{event="security"}[5m]) > 0
  annotations:
    summary: "Subscribe peer-IP mismatch (#1059) — possible stolen session_id replayed from a new IP"

- alert: AgentSubscribeIdentityMismatch
  expr: increase(yuzu_grpc_subscribe_identity_mismatch_total{event="security"}[5m]) > 0
  annotations:
    summary: "Subscribe mTLS identity mismatch (#1118) — possible stolen session_id replayed with a non-matching client cert"

# NAT-aware tolerated mismatch (#1128). yuzu_grpc_subscribe_peer_advisory_total
# {event="security",reason="mtls_identity_match|trusted_nat_cidr"} counts peer-IP
# mismatches that were DOWNGRADED to advisory (not rejected) under a NAT
# accommodation. A spike here ALONE is expected churn in multi-egress NAT
# deployments — do NOT alert on it bare. The actionable signal is the
# correlated form: advisory AND rejected mismatches rising together can mean a
# stolen-session replay landing inside a trusted range.
- alert: AgentSubscribePeerAdvisoryCorrelatedSpike
  expr: >
    increase(yuzu_grpc_subscribe_peer_advisory_total{event="security"}[5m]) > 0
    and increase(yuzu_grpc_subscribe_peer_mismatch_total{event="security"}[5m]) > 0
  annotations:
    summary: "Tolerated NAT peer-mismatches (#1128) coincide with rejected mismatches — investigate the reject events for a possible stolen-session replay inside a trusted range"

# Operator-visibility guard for --nat-trust-mtls-identity. Sustained
# mtls_identity_match advisories mean the (opt-in, off-by-default) mTLS-identity
# NAT accommodation is active — confirm it was enabled intentionally AND that
# client certs are PER-AGENT (a shared fleet cert makes this a replay bypass,
# gov UP-2). Long window: this should be rare; a steady stream is worth a look.
- alert: AgentSubscribeMtlsIdentityAdvisoryActive
  expr: increase(yuzu_grpc_subscribe_peer_advisory_total{event="security",reason="mtls_identity_match"}[30m]) > 0
  for: 30m
  annotations:
    summary: "--nat-trust-mtls-identity is relaxing peer-IP binding via mTLS-identity match — verify it was enabled deliberately and that client certs are per-agent (shared cert = session-replay bypass)"

- alert: AgentRegisterDeniedFlood
  expr: rate(yuzu_register_denied_total{event="security"}[5m]) > 1
  for: 5m
  annotations:
    summary: "Admin-denied identity repeatedly attempting Register (#1067) — credential-abuse / denied-flood signal"
```

## Labels

Metrics carry a standard set of labels for filtering and grouping in queries.

| Label | Description | Example values |
|---|---|---|
| `agent_id` | Unique agent identifier | `agent-001`, `dc2-web-14` |
| `plugin` | Plugin that produced the metric | `hardware_info`, `network_info` |
| `method` | HTTP method or RPC name | `GET`, `POST`, `Heartbeat` |
| `status` | HTTP status code or outcome | `200`, `500`, `success`, `failure` |
| `os` | Agent operating system | `windows`, `linux`, `darwin` |
| `arch` | Agent CPU architecture | `x64`, `arm64` |
| `principal_class` | Actor class on HTTP request counts (closed set, ADR-1005). `human`/`agent`/`none` classify by credential presentation (traffic shape); `engine` classifies the RESOLVED session (a resolved engine-principal request) — see `docs/observability-conventions.md` for the hybrid-basis contract. Never an authorization signal. As of PR 4.5, `agent` no longer includes engine-principal traffic — a panel/alert summing `agent` across the 4.5 deploy boundary shows a step-down that is a reclassification artifact, not a traffic change. | `human`, `agent`, `none`, `engine` |

## On-behalf-of rejection metric (ADR-1005)

```
# HELP yuzu_onbehalf_rejected_total Requests rejected for carrying a reserved on-behalf-of header/metadata key (ADR-1005) by surface
# TYPE yuzu_onbehalf_rejected_total counter
yuzu_onbehalf_rejected_total{surface="http",event="security"} 0
yuzu_onbehalf_rejected_total{surface="grpc",event="security"} 0
```

Both series are pre-seeded to `0` at startup, so `absent()` alerts stay
meaningful. Any non-zero value means a client asserted it was acting on
another principal's behalf via a reserved header (HTTP `403`) or gRPC
metadata key (call cancelled) — see `docs/auth-architecture.md`
("On-behalf-of assertions rejected") for the reserved-name list. This event
deliberately has **no audit row**: the rejection fires pre-authentication, so
there is no resolved principal to attribute — the metric (with
`event="security"`, SIEM-routable per the observability conventions) is the
signal. Alert on `increase(yuzu_onbehalf_rejected_total[1h]) > 0` if you want
notification of any attempt.

## Per-principal quota metric (PR 4.4, ADR-1005 class engine principals)

```
# HELP yuzu_server_principal_quota_exhausted_total Per-principal quota-cap exhaustions by side and limit dimension
# TYPE yuzu_server_principal_quota_exhausted_total counter
yuzu_server_principal_quota_exhausted_total{side="engine",limit="concurrency"} 0
yuzu_server_principal_quota_exhausted_total{side="engine",limit="rate"} 0
yuzu_server_principal_quota_exhausted_total{side="operator",limit="concurrency"} 0
yuzu_server_principal_quota_exhausted_total{side="operator",limit="rate"} 0

# HELP yuzu_server_principal_quota_admits_total Per-principal quota-cap admits (successful try_acquire) by side
# TYPE yuzu_server_principal_quota_admits_total counter
yuzu_server_principal_quota_admits_total{side="engine"} 0
yuzu_server_principal_quota_admits_total{side="operator"} 0
```

All 4 `exhausted_total` series (the closed `side` × `limit` cross-product)
are pre-seeded to `0` at startup, so `absent()` alerts stay meaningful. The
gate applies only to `principal_kind=="engine"` sessions (username
`engine:<slug>`) at the server's single pre-routing chokepoint —
human/agent/anonymous traffic never touches it. `side` distinguishes which
principal's budget was debited (`engine` is the only value emitted in PR
4.4; `operator` is pre-seeded but dormant — it activates in Phase 5 when
delegation debits the delegating operator's side too). `limit` distinguishes
which of the two independent caps rejected the request: `concurrency`
(in-flight requests, tunable via
`--principal-max-concurrency`/`YUZU_PRINCIPAL_MAX_CONCURRENCY`, default 16)
or `rate` (token-bucket requests/second, tunable via
`--principal-rate-limit`/`YUZU_PRINCIPAL_RATE_LIMIT`, default 20.0/s, burst
= 2x rate). Neither label carries `principal_id` — bounded cardinality only.
This is an **operational** counter, not `event="security"` — a quota cap
hit is expected steady-state behaviour for a busy engine principal, not an
attack signal — and it deliberately has **no audit row** for the same
high-frequency-operational reason (see `docs/user-manual/audit-log.md`).

`yuzu_server_principal_quota_admits_total{side}` is the admits companion —
every request that clears **both** the concurrency and rate checks
increments it once. It exists so the exhaustion *rate* is computable rather
than just the raw exhaustion count: `exhausted / (exhausted + admits)`. A
raw exhaustion counter alone can't distinguish "an engine principal is
hitting its cap on a small fraction of a huge request volume" (healthy, cap
doing its job) from "almost everything this engine principal sends is being
rejected" (self-brick, usually right after a config change that set the cap
too low) — the ratio against admits is what tells them apart. Both series
are pre-seeded to `0` at startup for the same reason; `side="engine"` is the
only value emitted today (`side="operator"` is pre-seeded but dormant until
Phase 5, same as the exhaustion counter). **Streaming requests are
included** — a streaming request now takes a concurrency slot (held for the
stream's lifetime) plus the rate debit, same as any other engine request
(UP-1 hardening fix; see the streaming note below) — so a streaming request
is counted here exactly like any other admitted engine request.

**Streaming/SSE note (UP-1).** Streaming/SSE requests are **not** exempt
from either dimension of this cap — they take a concurrency slot held for
the stream's lifetime (released when the stream ends), plus the rate debit,
the same two caps as any other engine request. An earlier revision of this
primitive treated streaming as rate-only and concurrency-exempt, which left
an engine principal able to open an unbounded number of concurrent streams;
that gap is closed.

**Per-instance caveat:** the cap is enforced in one process's memory. A
multi-replica deployment's **effective ceiling is `configured_cap x
replica_count`**, not the configured cap alone — each replica enforces the
cap independently against its own share of traffic, so N replicas give each
engine principal up to N x the configured per-replica cap in aggregate, not
one fleet-wide budget. Durable, cross-instance quota is a Phase-8 follow-up.
When alerting or sizing a cap for a multi-replica deployment, account for
this multiplier — a cap sized for the single-instance default may be far too
generous fleet-wide. Alert on `increase(yuzu_server_principal_quota_exhausted_total{side="engine"}[1h]) > 0`
if you want notification that an engine principal is regularly hitting its
cap (may indicate the cap is tuned too low for its workload, or a runaway
caller).

## Engine-credential confirm metric (#2404)

```
# HELP yuzu_engine_principal_confirm_total Engine-credential rotation confirm outcomes by surface (rest|mcp) and result (success|conflict|client_error|transient); store-reaching calls only, pre-store denials excluded (#2404)
# TYPE yuzu_engine_principal_confirm_total counter
yuzu_engine_principal_confirm_total{surface="rest",result="success"} 0
yuzu_engine_principal_confirm_total{surface="rest",result="conflict"} 0
yuzu_engine_principal_confirm_total{surface="rest",result="client_error"} 0
yuzu_engine_principal_confirm_total{surface="rest",result="transient"} 0
yuzu_engine_principal_confirm_total{surface="mcp",result="success"} 0
yuzu_engine_principal_confirm_total{surface="mcp",result="conflict"} 0
yuzu_engine_principal_confirm_total{surface="mcp",result="client_error"} 0
yuzu_engine_principal_confirm_total{surface="mcp",result="transient"} 0
```

All 8 series (the closed `surface` × `result` cross-product) are pre-seeded to
`0` at startup so `absent()` alerts stay meaningful. The family makes a
credential-**confirm** retry storm alertable, which `yuzu_http_requests_total`
cannot show (it has no per-route label). `result` mirrors the shared
store-error taxonomy (`engine_store_error_class.hpp`): `conflict` is a terminal
409/kInvalidParams (a replay after the rotation already resolved, a moved-on
pin, or unresolved rotation metadata — the client must not blindly retry),
`client_error` is a 400 (more-than-two or non-engine active credentials),
`transient` is a retryable 503 (store unavailable, lock contention, a persist
failure, or the ambiguous empty/malformed-pair "no in-flight rotation"), and
`success` is a completed confirm.

**Scope contract.** Counted only when a confirm reaches `ApiTokenStore::confirm_rotation`
**or** trips the store-open guard (which increments `result="transient"`);
pre-store denials — permission, MFA step-up, input validation, and the MCP
supervised approval-gate's consumed-ticket replay (`approval already used`) —
are deliberately **excluded**, so the label set stays a fact about store
outcomes rather than a catch-all endpoint tally. The increment is stamped
**before** the audit emission, so an audit-store failure cannot suppress it.
Wired on **both** surfaces (the `surface` label prevents double-count) because
either a REST or an agentic MCP client can drive the #2404 replay shape.

**Operational, not `event="security"`.** A replay conflict is an expected
agent-retry pattern, not an attack signal; the counter carries no `principal_id`
label (bounded cardinality only) — pair it with the
`engine_principal.credential.confirm` audit rows for per-principal forensics
(metric-is-the-signal / audit-row-is-the-evidence). A useful alert is
`increase(yuzu_engine_principal_confirm_total{result="conflict"}[15m]) > <n>`
to catch a client stuck replaying a resolved confirm, and
`increase(...{result="transient"}[15m])` for a genuine store-health storm.

**Semantics for alert authors:** this counts confirm **attempts** that reach
the store, not logical rotations — a client retrying a `transient` blip 20 times
before it succeeds adds 20 to `transient` for one rotation. Pick the threshold
`<n>` relative to your fleet's typical retry count, not your rotation cadence.
Also cross-reference `yuzu_engine_principal_rotation_sweep_failures_total`: a
`result="conflict"` cluster correlating with a non-zero, sustained sweep-failure
count is the prolonged-sweep-outage signature (a predecessor's overlap window
never closes, so a confirm surfaces the `unresolved rotation metadata` state) —
**inspect the credential before revoking**, since in that state the sole active
credential is the good survivor.

**`yuzu_rotation_sweep_capped_total`** (governance UP-5/UP-6, no labels,
shared across engine-credential and human API-token rotation pairs — deliberately
kind-neutral naming, unlike `yuzu_engine_principal_rotation_sweep_failures_total`
above, because a capped tick is a tick-level property, not attributable to one
kind's rows; the sibling failures counter keeps its engine-scoped name only
because renaming an already-shipped series would break existing alerts): a
rotation sweep tick found MORE eligible predecessors than its per-tick
auto-revoke cap (`kMaxAutoRevokesPerTick`, `api_token_store.cpp`) and processed
only the cap's worth, deferring the rest to later ticks — the
clock-guarded-retention routed concern's mandatory unconditional cap, applied
here (a single forward NTP step must degrade to a bounded multi-tick drain,
never a fleet-wide cutover in one tick). A sustained non-zero rate means the
fleet has more concurrent in-flight rotations than the cap comfortably drains
— raise the cap, or find out why so many rotations are in flight at once,
rather than ignore it.

## Rotation-sweep clock guard metrics (#2964)

The T12 sweep now carries the full seven-part clock-guarded-retention shape
(the routed concern in CLAUDE.md), not just the cap above. These are the
remaining series it registers, all kind-neutral and shared across
engine-credential and human API-token rotation pairs for the same reason
`yuzu_rotation_sweep_capped_total` is — the clock guard's verdict is a
tick-level property of the sweep itself, not attributable to one kind's
rows. Background and the decision rule: `audit_retention_rules.hpp::classify`
(reused, not forked) and `ApiTokenStore::sweep_expired_rotations`
(`api_token_store.cpp`), pinned by `tests/unit/server/test_api_token_store.cpp`.

| Metric | Type | Meaning |
|---|---|---|
| `yuzu_rotation_sweep_declined_total` | counter | Sweep ticks the clock guard **declined** — an implausible PostgreSQL clock reading (bad durable state), or a big step since the last accepted tick. A big-step decline is **not necessarily a clock fault**: at this store's 3600s threshold (`kRotationSweepBigStepSecs`), the most common trigger is a multi-tick gap with no clock fault at all — a maintenance window, a database failover, or an instance left off overnight all cross it just as a clock jump would. Check both before assuming the clock moved. This store does **not** adopt the clock-guarded-retention routed concern's would-wipe probe (see `api_token_store.cpp`'s DELIBERATE NON-ADOPTION comment near `kRotationSweepBigStepSecs`'s definition) — a `Wipe`-classified decline cannot occur here. Nothing is auto-revoked on a declined tick — both credentials in every affected pair stay active for at least one more tick. Excludes the bootstrap case (see `yuzu_rotation_sweep_bootstrap_declines_total` below), which is a separate, deliberately un-folded series routed on the raw `no_anchor` fact, never the classified anomaly — folding it in here would make an ordinary first-tick-after-upgrade decline indistinguishable from "the clock moved". Read alongside `yuzu_rotation_sweep_lock_skipped_total` and `yuzu_rotation_sweep_last_pass_timestamp_seconds` below, the same way `yuzu_server_audit_clock_anomaly_skips_total` is read alongside its own family. |
| `yuzu_rotation_sweep_lock_skipped_total` | counter | Sweep ticks this replica skipped because it did not hold the store-wide session advisory lock this tick. **Read this topology-aware, not as a flat "routine, ignore it" signal — its meaning inverts on deployment shape.** On a **single-replica deployment (the default)** this must be, and stay, exactly `0`: one dedicated sweep thread on a sequential 60-second loop cannot lose an election against itself, so any non-zero reading there means a *second writer* is holding the same session lock — a leaked lock from a crashed process, a botched blue-green cutover briefly overlapping two live instances, or an unauthorised second server pointed at the same DSN. On a genuinely **multi-replica** deployment, a roughly `(N-1)/N` steady-state rate per replica is expected and healthy — that is what "one replica wins the lock per tick" looks like under N contenders. This metric alone cannot tell you which deployment shape you are reading it against; know your own replica count first. Deliberately never logged per-tick even on the fault path (see the metric's own `describe()` text) — the per-tick log is reserved for a genuinely actionable decline, not this. `YuzuRotationSweepLockContentionUnexpected` (`docs/prometheus/yuzu-alerts.yml`) is a single-replica-scoped alert on it — read its own comment before enabling it on a multi-replica deployment. Triage: `docs/ops-runbooks/rotation-sweep-clock-guard.md`. |
| `yuzu_rotation_sweep_capped_total` | counter | Documented above — included here only for the cross-reference; see that paragraph. |
| `yuzu_rotation_sweep_bootstrap_declines_total` | counter | Split out from `yuzu_rotation_sweep_declined_total` above, the same way `yuzu_server_audit_retention_bootstrap_declines_total` (#2579) is split out from `yuzu_server_audit_clock_anomaly_skips_total` — a decline because the durable anchor has never yet settled (`no_anchor` in the shared `Facts` struct) asserts only that nothing can yet be ruled out, a materially weaker and differently-actionable claim than "the clock moved", and folding it into the general decline series would make the two indistinguishable from the metric alone. Expect 0 or 1 per database (the declining pass also settles `rotation_retention_meta.bootstrap_settled`, so the next tick proceeds with a comparison point); a climbing value means the anchor is not surviving between ticks. |
| `yuzu_rotation_sweep_last_pass_timestamp_seconds` | gauge | Exports `rotation_retention_meta.last_pass_now` — the wall-clock (PostgreSQL-authoritative) reading of the most recent sweep tick to reach a **classification** verdict, `0` if none has ever run on this database (pre-seeded at boot, matching the counters above — the series is present at `0`, never absent-until-first-tick). Surviving restarts the same way `yuzu_server_audit_retention_last_pass_unixtime` does. Stamped on `Ok` and `Declined` outcomes **only** — every `Failed` outcome leaves `sweep_expired_rotations`' classification transaction uncommitted (rolled back), including its own attempted re-stamp of this same reading, so a permanently failing tick never refreshes this gauge and staleness correctly accumulates against it. A missing `rotation_retention_meta` table specifically (e.g. #3013's migration-numbering collision) is **not** an example of that at construction time: `ApiTokenStore`'s own post-migration smoke-read catches it before the store ever opens, and the whole server refuses to start (ADR-0012 §1) — no tick ever runs, so there is no gauge to go stale and no scrape to read it from (the signature there is the process not being up at all, not this gauge). The "permanently failing tick" shape this sentence describes is the RUNTIME case only — the table going missing (e.g. an out-of-band `DROP TABLE`) AFTER a successful boot, which the construction-time smoke-read cannot see. **This is what closes the liveness gap the counters above cannot**: an `Ok`, non-capped, non-lossy tick — the common case on a healthy fleet — increments none of them, so a sweep thread that has silently died reads identically to a quiet healthy one on every series here except this gauge. `YuzuRotationSweepNotRunning` (`docs/prometheus/yuzu-alerts.yml`) alerts on its staleness. **What this gauge does NOT prove**: freshness means the classification transaction reached a verdict, not that any predecessor was actually revoked — an `Ok` tick that loses every one of its per-pair revoke transactions to pool contention still commits the classification transaction (and this gauge's timestamp) on schedule. See `yuzu_rotation_sweep_lost_revocations_total` below for that failure mode; read the two together. |
| `yuzu_rotation_sweep_lost_revocations_total` | counter | Cumulative predecessors an accepted (`Ok`) tick selected for auto-revoke whose per-pair revoke transaction genuinely **failed** (pool/lock/query fault — not the benign already-resolved idempotent no-op, which is not counted). Distinct from a whole-tick failure (`yuzu_engine_principal_rotation_sweep_failures_total`, which means the classification itself never reached a verdict): this counter is what makes an `Ok` tick that silently lost some or all of its revocations distinguishable from a genuinely healthy one — before it existed, both looked identical (verdict reached, last-pass gauge fresh, no other counter moved). Value is the count of predecessors affected that tick, not a 0/1 flag, so `increase()` over a window gives the actual scale, not just whether it happened. Each affected predecessor remains eligible and is retried on the next tick. |

A server predating this metrics family, or a scrape config dropping the
`yuzu_rotation_sweep_*` series, reads as a silently-healthy sweep — none of
these are paired with their own "series is absent" companion alert today
(unlike `YuzuAuditRetentionNotRunning`/`YuzuAuditRetentionMetricMissing`);
that gap is tracked, not closed, by this round.

## Human API-token confirm metric (P2 #11)

```
# HELP yuzu_api_token_confirm_total Human API-token rotation confirm outcomes by surface (rest|mcp) and result (success|conflict|client_error|transient); store-reaching calls only, pre-store denials excluded - the human-owned twin of yuzu_engine_principal_confirm_total
# TYPE yuzu_api_token_confirm_total counter
yuzu_api_token_confirm_total{surface="rest",result="success"} 0
yuzu_api_token_confirm_total{surface="rest",result="conflict"} 0
yuzu_api_token_confirm_total{surface="rest",result="client_error"} 0
yuzu_api_token_confirm_total{surface="rest",result="transient"} 0
yuzu_api_token_confirm_total{surface="mcp",result="success"} 0
yuzu_api_token_confirm_total{surface="mcp",result="conflict"} 0
yuzu_api_token_confirm_total{surface="mcp",result="client_error"} 0
yuzu_api_token_confirm_total{surface="mcp",result="transient"} 0
```

The human-owned twin of [`yuzu_engine_principal_confirm_total`](#engine-credential-confirm-metric-2404)
directly above — same closed `surface` x `result` cross-product (8 series),
pre-seeded to `0` at startup for the same `absent()`-alert reason, and the
same intended scope contract: counted only when a confirm reaches the
credential store or trips the store-open guard (`result="transient"`),
excluding pre-store denials (permission, input validation, an MCP
approval-gate replay) so the label set stays a fact about store outcomes.
`result` mirrors the same store-error taxonomy as the engine family.

**Live — both transports increment this family.** It is registered and
pre-seeded (`rotation_sweep_naming.hpp`'s `kApiTokenConfirmTotalMetric`
symbol, shared by the registration site and both increment call sites so a
typo can't silently create a second, uncounted shadow series) at
`rest_api_v1.cpp`'s `POST /api/v1/tokens/{id}/confirm` handler
(`surface="rest"`) and `mcp_server.cpp`'s `confirm_api_token_rotation` tool
handler (`surface="mcp"`). Treat it exactly like the engine family:
`increase(yuzu_api_token_confirm_total{result="conflict"}[15m]) > <n>`
for a client stuck replaying a resolved confirm, paired with whatever audit
action the confirm-rotation piece emits for per-principal forensics — the
metric is the signal, the audit row is the evidence. See
[audit-log.md](audit-log.md) for the `api_token.rotation.auto_revoke` /
`.successor_unused` rows this piece DOES ship (the sweep-driven auto-revoke
and successor-unused-warning half of human token rotation, distinct from
confirm).

## MCP poll-rate metric (#3344)

```
# HELP yuzu_mcp_poll_total MCP result-poll tool calls by verdict (get_execution_status, query_responses, get_bundle_result). not_ready: the success payload carried a retry_after_ms poll hint; ready: served terminal/complete without one. Excludes pre-verdict denials.
# TYPE yuzu_mcp_poll_total counter
yuzu_mcp_poll_total{tool="get_execution_status",result="ready"} 0
yuzu_mcp_poll_total{tool="get_execution_status",result="not_ready"} 0
yuzu_mcp_poll_total{tool="query_responses",result="ready"} 0
yuzu_mcp_poll_total{tool="query_responses",result="not_ready"} 0
yuzu_mcp_poll_total{tool="get_bundle_result",result="ready"} 0
yuzu_mcp_poll_total{tool="get_bundle_result",result="not_ready"} 0
```

Closed `tool` (the three success-shaped result-poll tools) x `result`
(`ready`|`not_ready`) cross-product (6 series), pre-seeded to `0` at startup
(`server.cpp`), symbol shared between the `describe()` site and the
increment site via `mcp::kMcpPollTotalMetric` (`mcp_retry.hpp`) so the two
cannot silently diverge into a shadow series — same precedent as
`kApiTokenConfirmTotalMetric` above. **Scope contract:** counted only when a
call reaches a served verdict — pre-verdict denials (tier, permission,
invalid-params, not-found) are excluded, already visible via the existing
denial counters and A4 envelopes, so the label set stays a fact about poll
outcomes. For `query_responses` specifically, a call whose in-flight-ness
could not be determined (an `instruction_id`-only query, or an
`execution_id` the tracker can't resolve) increments **neither** series —
it was never checked, so folding it into `ready` would understate the
`not_ready` fraction. Deliberately **operational, not `event="security"`** —
a high poll rate is expected agentic-worker behaviour, not an anomaly.

**Purpose: data-driven re-tuning, not alerting.** The named `retry_after_ms`
floor constants (`kMcpStoreFaultRetryMs`, `kMcpResultPollRetryMs`, etc. —
`mcp_retry.hpp`) were shipped with a *mechanical* derivation (no
dispatch-to-first-result latency histogram exists to measure from —
`yuzu_command_duration_seconds` is full command completion, not
first-result) rather than a measured one. This series' `not_ready` fraction
is the data that lets a future change re-derive them from real evidence
instead of guessing again — same "tuning signal, not an alert" posture as
`yuzu_nvd_sync_failures_total` above; no alert rule is expected or wired.
Example query for "is the floor for this tool too conservative or too
aggressive":

```promql
sum(rate(yuzu_mcp_poll_total{result="not_ready"}[15m])) by (tool)
/
sum(rate(yuzu_mcp_poll_total[15m])) by (tool)
```

See [docs/mcp-server.md → `retry_after_ms` floors](../mcp-server.md#retry_after_ms-floors-3344)
for the full constant table this metric exists to tune.

## Rotation-durability tamper/corruption gauges (#2961)

```
# HELP yuzu_server_rotation_pair_resolve_failures_total resolve_rotation_pair_after_revoke partner-clear failures that were swallowed - the revoke they follow has already committed, so they cannot fail the caller. Leaves stale rotation metadata on the surviving partner; NOT a lockout risk (the sweep cannot auto-revoke a stranded partner). Non-zero means inspect manually.
# TYPE yuzu_server_rotation_pair_resolve_failures_total gauge
yuzu_server_rotation_pair_resolve_failures_total 0
# HELP yuzu_server_rotation_initiator_disagreements_total resolve_rotation_initiator RAM-vs-durable disagreements - not reachable in normal operation; non-zero means inspect api_tokens.rotation_initiator for out-of-band tampering or corruption.
# TYPE yuzu_server_rotation_initiator_disagreements_total gauge
yuzu_server_rotation_initiator_disagreements_total 0
```

Both are `ApiTokenStore` counters, gauge-published from a store accessor on
every `/metrics` scrape (same shape as `yuzu_server_token_cache_size` above
— no counter pre-seed needed, since the scrape callback sets the value every
time rather than relying on a startup registration).

**`yuzu_server_rotation_initiator_disagreements_total`** is the tamper/
corruption signal on an authorization input: `resolve_rotation_initiator`
(`api_token_store.cpp`) refuses to resolve a confirm's initiator when the
RAM grace-cache copy of `requesting_user` and the durable
`api_tokens.rotation_initiator` column DISAGREE, rather than silently
preferring either. Both sources are written from the SAME `requesting_user`
inside the SAME locked mint transaction, so this is **not reachable through
any live code path** — a non-zero value means an out-of-band write to
`api_tokens.rotation_initiator` (direct SQL, a restored/edited backup) or a
future bug, never normal operation. The corresponding confirm call fails
closed with `rotation confirmation unavailable` (409/`Conflict`); this
gauge is the only durable, alertable trace of *why* it failed closed (the
error string alone does not distinguish a genuine "never stamped" pre-v3
pair from a disagreement). Alert on any nonzero value —
`yuzu_server_rotation_initiator_disagreements_total > 0` — rather than a
rate threshold: even one occurrence warrants manual inspection of the
row's history.

**`yuzu_server_rotation_pair_resolve_failures_total`** covers a distinct,
operability-only failure: `resolve_rotation_pair_after_revoke` failing to
clear the surviving partner's rotation state after a revoke has already
committed. See the metric's own `HELP` text above for the full scope —
stale metadata, not a lockout risk, since the sweep structurally cannot
auto-revoke a row this leaves stranded.

## Access review metrics

Periodic access reviews (SOC 2 CC6.2, `docs/auth-architecture.md` "Periodic
access reviews") shipped with zero metrics; the hardening round added four
bounded-label series wired at the REST handlers (`rest_api_v1.cpp`) only —
the MCP twins are not double-counted.

```
# HELP yuzu_access_review_export_total Access review evidence exports (GET /api/v1/access-reviews/export), by format
# TYPE yuzu_access_review_export_total counter
yuzu_access_review_export_total{format="json"} 0
yuzu_access_review_export_total{format="csv"} 0

# HELP yuzu_access_review_export_duration_seconds Latency of the cross-principal grant-population read (build_access_review) behind GET /api/v1/access-reviews/export
# TYPE yuzu_access_review_export_duration_seconds histogram

# HELP yuzu_access_review_campaigns_opened_total Access review campaigns opened (POST /api/v1/access-reviews)
# TYPE yuzu_access_review_campaigns_opened_total counter
yuzu_access_review_campaigns_opened_total 0

# HELP yuzu_access_review_attestations_total Access review reviewer decisions recorded (POST /api/v1/access-reviews/{id}/attestations), by decision
# TYPE yuzu_access_review_attestations_total counter
yuzu_access_review_attestations_total{decision="attested"} 0
yuzu_access_review_attestations_total{decision="flagged_revoke"} 0
```

- **`yuzu_access_review_export_total{format}`** — counter, `format` ∈
  {`json`, `csv`}, pre-seeded to `0` at startup. Increments once per
  successful `GET /api/v1/access-reviews/export` call, split by which
  format was requested — a sustained shift toward `csv` typically means an
  auditor/spreadsheet workflow is in play.
- **`yuzu_access_review_export_duration_seconds`** — histogram (default
  bucket ladder, see "Histogram buckets" below), the wall-clock time of the
  cross-principal grant-population read (`build_access_review`) behind the
  export, timed regardless of success/failure outcome — a slow/failing read
  is exactly what an operator debugging a `503` needs latency evidence for.
- **`yuzu_access_review_campaigns_opened_total`** — counter, no labels.
  Increments once per successful `POST /api/v1/access-reviews` — the rate
  this fires at is the empirical "how often does the org actually run a
  review" cadence signal (compare against the org's stated review policy).
- **`yuzu_access_review_attestations_total{decision}`** — counter,
  `decision` ∈ {`attested`, `flagged_revoke`}, pre-seeded to `0` at startup.
  Increments once per successful `POST
  /api/v1/access-reviews/{id}/attestations` call, split by the reviewer's
  decision. `flagged_revoke` counts recorded evidence only — it never
  itself revokes anything (flag ≠ revoke, see `docs/auth-architecture.md`);
  a rising `flagged_revoke` count is a worklist size for whoever acts on
  the flags, not an automatic remediation trigger.

None of the four carries `event="security"` — a review export or an
attestation decision is expected, privileged, self-audited operator
activity (own audit rows: `access_review.exported`, `.campaign_opened`,
`.attested`/`.flagged`), not an anomaly signal. Bounded-label series
(`format`, `decision`) are pre-seeded to `0` at startup per the standing
convention in `docs/observability-conventions.md`, so `absent()`-style
alerts stay meaningful.

## Agent OTA pull metrics (#913, #911, #416)

```
# HELP yuzu_ota_download_admission_total Agent OTA DownloadUpdate admission decisions by outcome
# TYPE yuzu_ota_download_admission_total counter
yuzu_ota_download_admission_total{decision="admitted"} 0
yuzu_ota_download_admission_total{decision="rejected_concurrency"} 0
yuzu_ota_download_admission_total{decision="rejected_rate"} 0
yuzu_ota_download_admission_total{decision="rejected_total"} 0

# HELP yuzu_ota_download_refund_total Agent OTA rate tokens returned after a server-attributable failure, by reason
# TYPE yuzu_ota_download_refund_total counter
yuzu_ota_download_refund_total{reason="registry_unavailable"} 0
yuzu_ota_download_refund_total{reason="version_not_found"} 0
yuzu_ota_download_refund_total{reason="package_missing"} 0
yuzu_ota_download_refund_total{reason="transfer_deadline"} 0
yuzu_ota_download_refund_total{reason="chunk_deadline"} 0

# HELP yuzu_ota_download_deadline_exceeded_total Agent OTA DownloadUpdate transfers aborted by a server-imposed deadline, by phase
# TYPE yuzu_ota_download_deadline_exceeded_total counter
yuzu_ota_download_deadline_exceeded_total{phase="transfer"} 0
yuzu_ota_download_deadline_exceeded_total{phase="write"} 0

# HELP yuzu_ota_admission_key_mode_total Agent OTA admission keying actually used, by mode
# TYPE yuzu_ota_admission_key_mode_total counter
yuzu_ota_admission_key_mode_total{mode="cert"} 0
yuzu_ota_admission_key_mode_total{mode="peer_ip"} 0
yuzu_ota_admission_key_mode_total{mode="unknown"} 0

# HELP yuzu_grpc_ota_identity_rejected_total Agent OTA RPCs rejected for a missing or mismatched client certificate identity, by rpc and reason
# TYPE yuzu_grpc_ota_identity_rejected_total counter
yuzu_grpc_ota_identity_rejected_total{event="security",rpc="download_update",reason="agent_id_mismatch"} 0
...

# HELP yuzu_ota_download_peers_tracked Peers currently tracked by the OTA admission map
# TYPE yuzu_ota_download_peers_tracked gauge
yuzu_ota_download_peers_tracked 0

# HELP yuzu_ota_download_peers_capacity Configured ceiling on the OTA admission map (--ota-max-peers-tracked)
# TYPE yuzu_ota_download_peers_capacity gauge
yuzu_ota_download_peers_capacity 50000

# HELP yuzu_ota_download_peers_evicted_total Peers evicted from the OTA admission map by its cardinality ceiling
# TYPE yuzu_ota_download_peers_evicted_total counter
yuzu_ota_download_peers_evicted_total 0
```

Every closed series is pre-seeded to `0` at startup so `absent()` alerts stay
meaningful. Labels are bounded by construction — a peer identity or IP is
**never** a label value.

**Operational vs security.** The admission, deadline and keying counters are
**operational**: a concurrency or rate rejection is expected steady-state
behaviour during a fleet-wide update, not an attack signal (the same reasoning
that keeps the per-principal quota counters off `event="security"`).
`yuzu_grpc_ota_identity_rejected_total` is the exception and carries
`event="security"` (it counts all four rejection reasons; only three of them also
write an audit row — `no_client_identity` is metric-only, see
`docs/user-manual/audit-log.md`), because a failed certificate bind on an already-enrolled
agent's OTA pull is an authentication event; it mirrors
`yuzu_grpc_revoked_cert_total` and is paired with a
`session.ota_identity_rejected` audit row (the metric is the signal, the audit
row is the evidence). **This counter is complete; the audit row is not.** The row
is rate-limited to roughly two per second per (peer, RPC, reason), because that write is
synchronous, Postgres-backed, and sits ahead of the per-peer admission bound. Use
this counter to measure volume during a flood, and the rows for attribution.

`yuzu_ota_identity_audit_suppressed_total{rpc,reason}` counts the rows that were
NOT written because that bucket was exhausted, so the sampling is directly
observable rather than inferred from a gap between two other numbers. The bucket
key includes the denial `reason` deliberately: without it, a peer holding a
certificate from another CA in a multi-CA trust bundle could present
`CN=<victim agent id>` and spend the victim's allowance. Note that verb is deliberately distinct from
`session.identity_mismatch`, which is the Subscribe binding check and carries a
different `detail` shape — see `docs/user-manual/audit-log.md`.

**Reading `decision`.** `rejected_concurrency` means the peer already held
`--ota-max-concurrent-per-peer` parallel downloads — the primary bound, and the
one that should fire under an actual monopolisation attempt.
`rejected_total` means the SERVER-WIDE ceiling
(`--ota-max-concurrent-total`) was hit — the only bound that does not scale with a
caller's address space, so it is the one that fires under a distributed pull.
`rejected_rate` means the peer drained its token bucket, which is a much looser
secondary bound; sustained `rejected_rate` without `rejected_concurrency`
usually indicates the rate knobs are tuned too tightly for the fleet's retry
behaviour rather than an attack. `decision` is a genuine partition over calls that **reach the admission gate** —
exactly one per such call. It is deliberately not a partition of every received
`DownloadUpdate`: the on-behalf, revoked-certificate and positive-identity gates
return before admission and are counted by their own families, so this sum is
legitimately lower than
`yuzu_grpc_requests_total{method="DownloadUpdate",status="received"}`. A
divergence between the two is expected during an identity attack, not missing
accounting.

**Reading refunds.** `yuzu_ota_download_refund_total{reason}` is a SEPARATE
family, deliberately not a `decision="refunded"` label: a refunded request has
already been counted as `admitted`, so folding refunds into that family would
stop `decision` partitioning and make `sum(yuzu_ota_download_admission_total)`
double-count. A refund is issued only for a **server-attributable** failure —
a deadline the server imposed, an unavailable registry, a missing artifact, or
a version this server does not hold — and it is why a slow-link or flapping
agent cannot spend itself into a lockout. The `reason` label is what makes the
invariant checkable: in steady state the two deadline reasons together must
match `yuzu_ota_download_deadline_exceeded_total` exactly, and a growing gap
means a code path is aborting without refunding (this is what
the invariant a refund-divergence alert watches — the rule for it ships with the OTA alert group, separately). `version_not_found` is refunded on purpose
even though the peer chose the version: nothing is streamed, so no capacity is
consumed, and a staged rollout routinely has agents asking for versions a given
server does not hold.

**Reading the peer map.** `yuzu_ota_download_peers_capacity` publishes the
configured `--ota-max-peers-tracked` so alerts can express occupancy as a RATIO
rather than hardcoding a threshold that silently becomes wrong when an operator
retunes the flag. `yuzu_ota_download_peers_evicted_total` increments at the
moment the ceiling actually bites, so approaching the cap and hitting it are
distinguishable.

**Reading `mode`.** `cert` is the healthy case: admission is keyed on the
peer's certificate identity. `peer_ip` means the peer presented no client
certificate, so admission fell back to source IP — expected on a
default-certificate deployment where unenrolled agents are still bootstrapping,
but a sustained high `peer_ip` share on a fleet you believe is fully enrolled
is worth investigating. `unknown` should never appear; it means neither a
certificate nor a parseable peer address was available.

**Caveat — per-process.** These counters describe one server process. Behind a
load balancer the per-peer bounds they report are per-replica, not fleet-wide
(see `docs/user-manual/server-admin.md`).

### Agent-side signature refusals (#416/#3807)

Emitted by the AGENT, not the server, and therefore not scrapeable directly —
the agent has no `/metrics` endpoint. They reach an operator only by the route
described below.

| Metric | Type | Meaning |
|---|---|---|
| `yuzu_agent_ota_signature_refused_total{reason}` | counter | An OTA package was refused for a signature reason. `reason` is a closed set: `missing` (no signature, with `--update-require-signature` set), `untrusted` (the signer does not chain to the configured trust bundle, or its leaf lacks the codeSigning EKU, or **the trust bundle itself could not be read** — an unreadable or missing bundle proves nothing, so it is counted as a trust failure rather than a pass, and is the most likely cause if this counter jumps on a host right after a config change), `invalid` (the signature is malformed, or does not cover these bytes). Cumulative for the life of the agent process. |

**How it reaches you.** The total across all three reasons is carried on the
agent heartbeat as the status tag `yuzu.ota_signature_refused`, and the server
derives `yuzu_fleet_ota_signature_refusing_agents` from it. Nothing else reads
the tag. If you need per-reason detail for a specific endpoint, it is in that
endpoint's own log — the update path has no status-report RPC, so the reason
does not travel to the server.

## Histogram buckets

Most histogram metrics use the same default bucket boundaries (in seconds); a few carry a custom
ladder called out in their own row (including `yuzu_server_guardian_event_store_duration_seconds`
at 0.1ms-10s and `yuzu_pg_acquire_wait_seconds` into the 10-60s tail). The default:

```
0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
```

These buckets are suitable for request latency tracking. The range covers
sub-millisecond local operations through multi-second network calls.

## Prometheus scrape configuration

Add Yuzu to your Prometheus `prometheus.yml`. For local scrapers, no
credentials are needed. Remote scrapers need `--metrics-no-auth` on the
server or must provide authentication:

```yaml
scrape_configs:
  - job_name: 'yuzu-server'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: /metrics
    scheme: http
```

**Multiple servers:**

```yaml
scrape_configs:
  - job_name: 'yuzu-server'
    static_configs:
      - targets:
          - 'yuzu-primary.example.com:8080'
          - 'yuzu-secondary.example.com:8080'
    metrics_path: /metrics
    scheme: https
```

### Verifying the scrape

After adding the configuration, confirm that Prometheus is scraping
successfully:

```bash
# Check target status
curl -s 'http://localhost:9090/api/v1/targets' | jq '.data.activeTargets[] | select(.labels.job == "yuzu-server")'

# Query a metric
curl -s 'http://localhost:9090/api/v1/query?query=yuzu_agents_connected' | jq .
```

## Real-time event stream

### GET /events

The server exposes a Server-Sent Events (SSE) endpoint for real-time updates.
The dashboard uses this for live agent status, but any SSE client can consume
it. This endpoint requires authentication (session cookie).

```bash
curl -s -b cookies.txt -N 'http://localhost:8080/events'
```

**Example output:**

```
event: agent-online
data: agent-001

event: agent-offline
data: agent-003

event: command-status
data: cmd-20240319-001|success

event: output
data: agent-001|hardware_info|{"cpu":"Intel i7","ram_gb":32}
```

**Event types:**

| Event | Data format | Description |
|---|---|---|
| `agent-online` | `{agent_id}` | An agent established a gRPC connection |
| `agent-offline` | `{agent_id}` | An agent connection was lost |
| `pending-agent` | `{agent_id}` | An agent is awaiting enrollment approval |
| `command-status` | `{command_id}\|{status}` | An instruction finished executing |
| `output` | `{agent_id}\|{plugin}\|{data}` | Streaming output from an instruction |
| `timing` | `{command_id}\|{metric}={value}\|{phase}` | Execution timing data |

Note: event data is plain text (not JSON). Fields are pipe-delimited where
multiple values are present.

### Agent lifecycle via WatchEvents RPC

The gRPC `WatchEvents` RPC provides the same lifecycle events (connect,
disconnect, plugin load) over a bidirectional stream. This is used internally
by the gateway and can be consumed by custom integrations that prefer gRPC over
SSE.

## Fleet performance gauges (DEX)

Published on every fleet-health sweep (~15 s). A metric nobody reported is
**absent**, never zero; values are validated server-side (forged non-finite /
out-of-range readings are rejected).

| Metric | Type | Description |
|---|---|---|
| `yuzu_fleet_ota_signature_refusing_agents` | gauge | Endpoints that have refused at least one OTA update for a signature reason **since the agent process last started** (#416/#3807). Derived from the agents' heartbeat tag `yuzu.ota_signature_refused`, whose counter is cumulative and never resets — so read this as "has refused", not "is currently failing": an endpoint that refused once and has since updated cleanly still counts until it restarts, and a restart zeroes one that is still stuck. A RISING value is the actionable signal. This is the only server-side view of the state: the OTA path has no status-report RPC and the agent exposes no `/metrics` endpoint. Counts only endpoints currently reporting heartbeats — an agent that refused and then went offline drops out of the gauge. See [server-admin.md → Signing update binaries](server-admin.md#signing-update-binaries-416). |
| `yuzu_fleet_perf_reporting` | gauge | Devices contributing at least one perf metric this sweep (the same any-of-three definition the `/dex` Performance tab's Reporting card uses) |
| `yuzu_fleet_perf_cpu_pct{stat}` | gauge | Fleet CPU busy %, `stat` = `avg` / `p50` / `p90` / `max` |
| `yuzu_fleet_perf_commit_pct{stat}` | gauge | Fleet memory commit % of limit, same `stat` labels |
| `yuzu_fleet_perf_disk_lat_ms{stat}` | gauge | Fleet per-IO disk service time (ms), same `stat` labels |

**Per-OS breakdown (C1)** — the same rollup, additionally split by the
agent's OS (`os` = `windows` / `linux` / `darwin` / `unknown` / `other`,
same allowlist `yuzu_fleet_agents_by_os` uses). Published alongside the
fleet-wide families above, cleared and rebuilt every sweep (absent, never a
stale 0, for an OS nobody reported this cycle). Windows and Linux both have
a real heartbeat perf collector today; a `darwin` agent can be online
(`yuzu_fleet_agents_by_os{os="darwin"}` > 0) while never appearing in any
`yuzu_fleet_perf_os_*` series — that is honest absence, not a bug, until the
macOS collector ships. Never blend these into a cross-OS aggregate — that is
exactly what the fleet-wide families above already are:

| Metric | Type | Description |
|---|---|---|
| `yuzu_fleet_perf_os_reporting{os}` | gauge | Devices of that OS contributing at least one perf metric this sweep |
| `yuzu_fleet_perf_os_cpu_pct{stat,os}` | gauge | Per-OS CPU busy % |
| `yuzu_fleet_perf_os_commit_pct{stat,os}` | gauge | Per-OS memory commit % of limit |
| `yuzu_fleet_perf_os_disk_lat_ms{stat,os}` | gauge | Per-OS per-IO disk service time (ms) |

**Per-cohort export (opt-in)** — published only when a cohort export tag key
is configured (Settings → DEX alerts; `runtime_config` key
`dex_cohort_export_key`):

| Metric | Type | Description |
|---|---|---|
| `yuzu_fleet_perf_cohort_cpu_pct{cohort,stat}` | gauge | Per-cohort CPU busy % |
| `yuzu_fleet_perf_cohort_commit_pct{cohort,stat}` | gauge | Per-cohort memory commit % |
| `yuzu_fleet_perf_cohort_disk_lat_ms{cohort,stat}` | gauge | Per-cohort disk latency (ms) |
| `yuzu_fleet_perf_cohort_reporting{cohort}` | gauge | Reporting devices per exported cohort |
| `yuzu_fleet_perf_cohort_clipped` | gauge | Exportable cohorts dropped by the top-50 cardinality cap (a measured 0 when nothing was cut; **absent when the export is off** — use this gauge, not `absent()` on the cohort families, as the export-liveness probe) |

Cohorts under 10 reporting devices and cohorts beyond the top-50-by-population
cap never export; devices without the key export as `cohort="(untagged)"`.
Families clear on every sweep — series go absent, never stale. Alerting
recipe: `max_over_time(yuzu_fleet_perf_cohort_clipped[1m])` for liveness,
`yuzu_fleet_perf_cohort_clipped > 0 for 5m` for cap pressure; with the ~15 s
sweep cadence, scrape at ≤10 s intervals when the export is enabled. See the
label-exposure note under Security considerations before choosing a key.

## Fleet network gauges

Published on every fleet-health sweep (~15 s), fed from the `yuzu.net_*`
heartbeat tags (device-aggregate facts only — no per-destination data). A metric
nobody reported is **absent**, never zero. **Linux, Windows, and macOS agents
emit network facts** — macOS throughput only (retransmit + RTT deferred; see
[Network Quality](network.md) → Platform coverage). Windows reports throughput and an interval
retransmit rate but not RTT (per-connection RTT needs ESTATS — a later slice), so
`yuzu_fleet_net_rtt_ms` stays Linux-only for now (see
[Network Quality](network.md) → Platform coverage). The same numbers feed the
`/network` Overview cards, via the shared validators, so the gauges and the page
cannot disagree.

**Caveat — RTT is coarse.** `yuzu_fleet_net_rtt_ms` is a device-aggregate median
across whatever TCP connections are open (loopback / LAN / internet blended), so
treat it as a rough signal, not per-flow truth; actionable per-destination /
per-app latency is a later warehouse-tier slice.

**The `yuzu_fleet_net_*` series carry an `os` label** (`windows` / `linux` / …,
matching `yuzu_fleet_agents_by_os`) so reporting, RTT, and throughput are split
per OS, never blended — query and alert per OS (`sum(...)` a count for a fleet
total). **The retransmit rate is the exception:** the Windows rate is *system-wide*,
biased low, and not yet loss-validated (#1465), so it is **withheld from the gauge
entirely** (it still shows on the `/network` page + REST, caveated) —
`yuzu_fleet_net_retrans_pct` carries **only loss-validated OSes (Linux today)**.

| Metric | Type | Description |
|---|---|---|
| `yuzu_fleet_net_reporting{os}` | gauge | Devices **of that OS** whose latest heartbeat carried at least one network fact (the same any-of definition the `/network` Overview Reporting card uses) |
| `yuzu_fleet_net_retrans_reporting{os}` | gauge | Devices **of that OS** that contributed an interval retransmit **rate to the gauge** this cycle — a subset of `_reporting{os}` (a device can report RTT while its retransmit window is still warming). Denominator for `_retrans_pct{stat,os}`. Only loss-validated OSes appear (Linux today); a Windows device reports a retransmit fact but it is withheld from the gauge, so Windows is absent here |
| `yuzu_fleet_net_degraded{os}` | gauge | **Dormant (measurement-first).** Agents no longer emit the `net_degraded` fact — the old absolute-ratio threshold was empirically disproven, and a calibrated threshold needs real-fleet baseline data (a later slice). **Absent** unless some agent of that OS still emits the tag (e.g. mid rolling-upgrade) — treat absent as "not classified", never 0 as "healthy". Revived when the degraded classification lands |
| `yuzu_fleet_net_rtt_ms{stat,os}` | gauge | Fleet smoothed RTT in ms, `stat` = `avg` / `p50` / `p90` / `max`. RTT is reported by Linux only today, so `os="linux"` is the only series present |
| `yuzu_fleet_net_retrans_pct{stat,os}` | gauge | Fleet TCP **interval** retransmit rate %, `stat` + `os` labels. Per device this is ΔΣretransmits / ΔΣsegments smoothed over the last few heartbeats (recent-window loss), **not** the lifetime ratio. **Loss-validated OSes only:** Linux is a per-connection-sum rate (netem-validated). The Windows rate is **system-wide** (loopback-inclusive, biased low, not yet validated — see network.md and #1465) and is **withheld from this gauge** (it shows on the `/network` page + REST, caveated) until validated — so today `os="linux"` is the only series. When Windows is validated it joins as its own `os` series; never alert on a cross-OS aggregate |
| `yuzu_fleet_net_throughput_bps{stat,os}` | gauge | Fleet device network throughput in bytes/s (rx+tx, non-loopback), `stat` + `os` labels |

Network sampling shares the `--dex-disable` agent flag; disabling DEX also
disables the network heartbeat tags. **All six `yuzu_fleet_net_*` families are
cleared on every sweep and re-emitted per reporting OS** — a `(metric, os)`
nobody reported is absent, never stale or a fabricated 0 (`_degraded{os}` only
appears if an agent of that OS still emits the retired tag).

## SparkEngine fleet gauges

Published on every fleet-health sweep (~15 s), fed from the `yuzu.spark_*`
heartbeat tags. SparkEngine (ADR-0021 Stage-2) is the next-generation event-driven
detection engine; at **rung 1 it runs observe-only** (no consumer arms rules), so
every mechanism- and consumer-health counter below is **0** in production today —
`_reporting`, `_disabled`, `_failed` and `_mechanisms` are the four that carry live
signal, and none of them depends on a consumer being armed; the rest go live when
rung 2 arms real rules. A `(metric, os[, mechanism])` nobody reported is **absent**,
never a fabricated 0 (all twelve families are cleared and re-emitted every sweep, the
same idiom as `yuzu_fleet_net_*`). An agent started with `--spark-disable` reports
`spark_running=0` + `spark_disabled=1`: it is absent from `_reporting` and counted in
`_disabled`. An agent whose engine was enabled but **threw at boot** reports
`spark_running=0` with no `spark_disabled` key, and is counted in `_failed` — that
split is what makes a fleet-wide spark boot failure visible at all.

**All series carry an `os` label** — `file` and `registry` mechanisms are
Windows-only, `service` is Windows + Linux, macOS has none — so **query and alert
per OS, never `sum without(os)`** (a cross-OS aggregate is meaningless for a
single-platform mechanism). Five families additionally carry a `mechanism` label
(`file` / `registry` / `service`): `_mechanisms` is a live per-agent capability
gauge (see its own row above); `_watch_rejected`, `_quarantined` and `_slow_op`
are fleet **sums of monotonic per-agent counters**, so a bare `> 0` alert **latches**
until the reporting agent restarts — the shipped **counter** alert templates
(disabled until rung 2) use `increase(...[15m]) > 0` instead. `_unsupported` (F7,
#2298 rung 2) is the other gauge exception: a **live current gauge**, not a
counter - it can legally decrease, so it must never be alerted on with
`increase()`/latching logic; see its own row below. One rule ships
**active** today: `YuzuSparkBootFailed` on `_failed` (a per-sweep state gauge,
latch-free) — warning severity, 30m hold (see `docs/prometheus/yuzu-alerts.yml`,
group `yuzu-fleet-spark-rung1`).

**Staged-rollout example:** these series only exist for agents that have been
upgraded to a spark-capable (rung-1+) build. During a phased agent rollout of a
2,000-endpoint Linux fleet with 500 agents upgraded,
`yuzu_fleet_spark_reporting{os="linux"}` reads **500, not 2,000** — the other
1,500 agents are ABSENT (pre-rung-1), which is expected and is not a failure.
`_reporting` approaches the enrolled count as the rollout completes; only
`_failed` indicates something wrong.

| Metric | Type | Description |
|---|---|---|
| `yuzu_fleet_spark_reporting{os}` | gauge | Agents **of that OS** whose latest heartbeat reported the engine running (`spark_running=1`) — the denominator for the engine-level counters |
| `yuzu_fleet_spark_disabled{os}` | gauge | Agents **of that OS** running with the engine deliberately off (`--spark-disable`). An operator decision — expected to be non-zero in some fleets. **Do not alert on it** |
| `yuzu_fleet_spark_failed{os}` | gauge | Agents **of that OS** where the engine was ENABLED but boot-time instantiation **threw**, so the agent degraded to no-spark. Distinct from `_disabled` on purpose: this is a fault, not a choice — **alert on it** (the shipped `YuzuSparkBootFailed` rule does, warning severity). Without this series a fleet-wide spark boot failure would be invisible (a failed agent would look exactly like one that was never asked to run it) |
| `yuzu_fleet_spark_mechanisms{os,mechanism}` | gauge | Agents **of that OS** whose spark capability includes that mechanism (from the `spark_mechs` CSV). Counts only mechanisms that are registered **and functional**: one that started but could not bind its OS facility — most commonly a **containerised Linux host, which has no systemd system bus** — is reported inert and **excluded**, because every watch on it would be refused. A Registry sweeper or File worker that fails three consecutive passes is likewise reported inert and excluded, because it cannot serve watches until a pass succeeds (its watches are still accepted), and is counted again once a pass succeeds. An OS with agents in `_reporting` but no `{mechanism}` series either does not support it (e.g. no `file` on `linux`) or cannot use it there |
| `yuzu_fleet_spark_armed_faulted{os}` | gauge | Fleet sum of armed watches a mechanism reported deaf. A **live** gauge (recovers when the watch recovers), not cumulative — `> 0` means detection is silently down for that many watches. 0 at rung 1 (nothing armed) |
| `yuzu_fleet_spark_watch_rejected{os,mechanism}` | gauge | Fleet sum of cumulative watch-cap rejections (a rule that could not arm — denial-of-detection). 0 at rung 1 |
| `yuzu_fleet_spark_quarantined{os,mechanism}` | gauge | Fleet sum of work a mechanism had to abandon at stop() instead of completing: File - watches leaked to process lifetime (a structural leak); Registry - establishment probes still parked on a detached worker when the mechanism stopped (leaked-and-counted, self-disposing). Should stay 0. 0 at rung 1 |
| `yuzu_fleet_spark_slow_op{os,mechanism}` | gauge | Fleet sum of cumulative watch-establishment work past the mechanism's own threshold: File - a slow arm-path OS operation under its lock; Registry - an arm or re-arm obligation unestablished past its 50 ms health grace (a stalled, refused or admission-saturated watcher). 0 at rung 1 |
| `yuzu_fleet_spark_unsupported{os,mechanism}` | gauge | Fleet sum of rules **currently** classified `unsupported` - a known spark type with no mechanism on that host, enforced by **neither** backend (F7, #2298 rung 2). A **live** gauge recomputed every sweep, not cumulative - it can legally decrease (e.g. after a reconcile that finds the mechanism available, or the rule being disabled/removed). **0 today**: classification only runs once an agent's `prefer_spark` is enabled, which is not yet true anywhere in production (see `yuzu.guardian_backend`, still `legacy` fleet-wide). Once enabled, every rule on macOS reads `unsupported`, since macOS registers none of file/registry/service - routine and expected there, not page-worthy. A rule can also stay `unsupported` after a runtime-inert File or Registry episode ends, until the next reconcile or an agent restart (#4685; R5.7 (g)(1) in `docs/spark-stage2-guardian-consumer-design.md`) |
| `yuzu_fleet_spark_watch_faults{os}` | gauge | Fleet sum of cumulative post-arm watch-fault edges (`watch_faults_total`). 0 at rung 1 |
| `yuzu_fleet_spark_queued_dropped{os}` | gauge | Fleet sum of cumulative queued events dropped (bounded-queue overflow + shutdown). On the enforce lane (rung 3) a drop is a silent compliance failure. 0 at rung 1 |
| `yuzu_fleet_spark_consumer_errors{os}` | gauge | Fleet sum of cumulative queued handlers that threw (`consumer_errors_total`). 0 at rung 1 |

**Finding an inert mechanism from the fleet series.** Compare `_reporting` with ONE mechanism's series, per OS, and only where every agent of that OS is expected to run that mechanism (Windows and `file`, for example). Match on `instance` as well as `os`: each scraped server replica publishes its own copy of these series, and matching on `os` alone fails with `found duplicate series for the match group` as soon as two replicas are scraped (`on(os, instance)` also works where no `instance` label exists). The `or` fallback keeps the query firing when the mechanism series is absent on every agent, where a plain subtraction would return nothing:

```promql
yuzu_fleet_spark_reporting{os="windows"}
  - on(os, instance) (yuzu_fleet_spark_mechanisms{os="windows",mechanism="file"}
                      or on(os, instance) (yuzu_fleet_spark_reporting{os="windows"} * 0)) > 0
```

The Linux form is the same with `os="linux"` and `mechanism="service"` (the only Linux mechanism); it counts every agent without a systemd system bus, so every containerised agent, as a gap, and is only meaningful for a fleet that has none. macOS has no per-mechanism detector: it has no mechanism by design, so no series is published and there is nothing to compare.

Do NOT compare `_reporting` with the SUM over mechanisms. A healthy Windows agent contributes to three series (`file`, `registry`, `service`), so the sum is about 3N against N reporting, and a fleet with `file` dropped still sums to about 2N; the comparison stays quiet until the average agent has lost more than two of its three mechanisms, so it cannot detect one inert mechanism on Windows. On Linux the sum form fires only while at least one agent still reports `service`: a fleet in which every agent is inert publishes no `{os="linux"}` mechanism series at all, and the comparison (like a plain subtraction) then returns nothing.

The fleet series cannot tell a boot-time inert from a runtime one (a File worker or Registry sweeper that failed three consecutive passes and has not yet recovered); the agent log does, see [Diagnosing an inert File worker or Registry sweeper](guaranteed-state.md#diagnosing-an-inert-file-worker-or-registry-sweeper-windows). No alert on `yuzu_fleet_spark_mechanisms` ships today. One written against a runtime-capable mechanism needs a `for:` hold of at least two heartbeats (60 s at the default 30 s heartbeat) or a self-clearing episode will fire it, and a paging alert wants at least 10 minutes, tuned on fleet data. The per-agent comparison is above zero while any one agent is in an episode, so a `for:` hold protects against one agent's short episode, not against many independent short ones across a large fleet: tune the hold and a fleet-fraction threshold on fleet data. Shipping such an alert is a precondition for turning Spark detection on (`docs/spark-flip-gate.md`).

See [Guaranteed State → SparkEngine](guaranteed-state.md#sparkengine--the-next-generation-detection-engine-observe-only)
for the observe-only migration, the `--spark-disable` flag, and the per-rung
enforcement-posture table.

## Guardian metrics

| Metric | Type | Description |
|---|---|---|
| `yuzu_server_guardian_baselines_total` | gauge | Number of persisted Guardian Baselines. Refreshed on every `/metrics` scrape. |
| `yuzu_server_guardian_events_total` | gauge | Guardian events currently persisted in the store (post-reap). |
| `yuzu_server_guardian_events_written_total` | counter | Cumulative Guardian events ever written (pre-reap). Exposed as TYPE `counter` via `describe()`; the value is read from the store each scrape and set through the gauge API (the `Counter` type has no `set()`), and resets to the store's current total on restart. |
| `yuzu_server_guardian_events_dropped_total` | counter | Cumulative Guardian events dropped at ingest on an `event_id` PK/UNIQUE conflict where the incoming payload **MISMATCHES** the stored row — a forged-id pre-claim (#1360), or an agent `event_seq_` reset / clock skew carrying a *different* event. Benign idempotent redeliveries (matching payload) are **not** counted here; they are on `yuzu_server_guardian_events_redelivered_total`. `> 0` therefore distinguishes "no drift observed" from "drift silently discarded" **and** flags a possible forged-id campaign — a CC7.3 evidence signal; investigate a sustained climb, don't just widen the threshold. Exposed as TYPE `counter`, but **resets on server restart** (in-memory atomic), so alert on `increase(...[1h])` over a window. The bundled `YuzuGuardianEventsDropped` alert fires at **> 5 / 1h**: because reconnect churn no longer lands here, this is a low, security-relevant threshold, not a reconnect-baseline knob (see `docs/prometheus/yuzu-alerts.yml`). |
| `yuzu_server_guardian_events_redelivered_total` | counter | Cumulative **idempotent redeliveries** at ingest — an `event_id` PK conflict where the incoming payload **matches** the stored row across every immutable agent-supplied field. This is the durable agent lifecycle journal's expected crash-durable, duplicate-tolerant, bounded-retry redelivery (it re-sends on every reconnect) - not a guarantee of eventual delivery: an un-acked record that ages out of the 7-day retention window is a rare, counted loss, not silent - counted by `yuzu.guardian_journal_evicted_no_send_evidence`, an agent heartbeat `status_tag` (not itself a Prometheus series scraped here). That counter is in-memory only and resets on agent restart, so it is not a durable audit trail, and today there is no dashboard, REST, or MCP surface exposing it at all, per-agent or fleet-wide (tracked under #2298; see [Reconnect replay traffic](guaranteed-state.md#reconnect-replay-traffic-durable-lifecycle-journal) for the full network-flows picture). The event is not re-written, the DEX observers are not re-fired, and the compliance signal is untouched. **High is normal after an agent outage/reconnect — it is NOT a loss signal** (that is `..._events_dropped_total`). Exposed as TYPE `counter`; resets on server restart. |
| `yuzu_server_guardian_events_ingest_errors_total` | counter | Cumulative **operational** Guardian ingest faults — a failed `BEGIN`/`prepare`/`INSERT`/`COMMIT`, or a redelivery-compare `SELECT` that could not run (NOMEM/IOERR). A sustained rate means the ingest machinery is broken and event_id conflicts are going **unclassified**, so a genuine forged-id collision can escape `..._events_dropped_total` — hence the bundled `YuzuGuardianIngestErrors` alert (`increase(...[15m]) > 0`). Excludes malformed embedded-NUL input (rejected at the boundary; attacker-drivable, so kept off this operational signal). Resets on server restart. |
| `yuzu_server_guardian_events_reaped_total` | counter | Cumulative Guardian event rows deleted by the retention reaper (disposal evidence). Exposed as TYPE `counter` (store-read value set via the gauge API, like the other `_total` counters here). |
| `yuzu_server_guardian_event_store_duration_seconds{status}` | histogram | Server-side latency of `insert_event_classified` (the classify+store operation, PostgreSQL since ADR-0038) for one Guardian event, split by outcome `status` (`inserted`/`redelivered`/`conflict`/`error`). Only `redelivered`/`conflict` execute the redelivery byte-compare; `inserted` does projection+commit - so read the series per-status, not as an aggregate. Covers the direct-Subscribe and gateway-proxied ingest paths. Custom buckets `0.1ms-10s` (sub-ms resolution for the common case + a seconds tail for lock contention / connection-pool wait). Born at server start (all four status series present on `/metrics` from boot). This is a **validation** signal for the planned off-write-path compare (#2298) - it confirms a benchmarked gain survives real traffic; it is **not** the go/no-go decision, which needs a controlled concurrent benchmark (an aggregate histogram can't attribute latency to compare-CPU vs lock-wait vs transaction work). |
| `yuzu_server_guardian_reap_passes_total{result}` | counter | Cumulative retention-reap passes (`reap_expired()`, #2496 `gc_sweep` shape, ADR-0038), split by `result` ∈ {`swept`, `noop`, `declined`, `declined_no_anchor`, `failed`, `skipped_lock`}. `declined`/`declined_no_anchor` mean nothing was deleted on that pass — the clock-guard held back a sweep it judged unsafe; `declined_no_anchor` is the #2579 missing-anchor trigger specifically (no usable previous reading while rows are already expired), counted apart from the general `declined` bucket for the same reason `AuditStore`'s dedicated counter is separate from its clock-anomaly series: it asserts only that nothing can yet be ruled out, not that the clock moved. Expect at most one `declined_no_anchor` per database — the declining pass also settles the bootstrap marker, so the next pass proceeds. A single decline is the ordinary fresh-deploy case; a climbing value fires `YuzuGuardianReapAnchorNotSurviving` (`increase(...[24h]) > 1`, `docs/prometheus/yuzu-alerts.yml`). `skipped_lock` is a sibling replica sweeping concurrently, not a failure. See [Retention](guaranteed-state.md#retention). |
| `yuzu_server_guardian_read_degrade_total{reason,source}` | counter | Cumulative Guardian reads that could not answer from a healthy PG connection (interim, #2659), by `reason` (`store_not_open`/`pool_acquire_timeout`/`query_error`) and `source` — two sources on this ONE counter (#4856), with *different* consequences for the caller. `source="guardian_state"` is the DEX/observation family (crash summary, top apps, device score inputs, `dex_read<>`/`dex_observation`) — these fail **soft**: the caller serves an empty/degraded result rather than an error, so a degraded dashboard can read as "0 crashes" and this counter/the sampled warn log are the only external tell. `source="guardian_rules"` is the AUTHORITATIVE rule/status reads (`get_rule`/`list_rules`/`agent_rule_statuses`/`agent_rule_statuses_for_agent`/`rule_names`/`rule_names_for`/`errored_rule_count`) — the read itself returns a typed `std::expected` error rather than a silent empty/stale result, and **most** callers fail hard on it (abort the push/reconcile/status surface); this is not universal, though — several `guardian_routes.cpp` dashboard renders call `list_rules().value_or({})` and fall back to an empty rule list on a degrade, and `guardian_ingest.cpp`'s event-severity enrichment folds a degraded `get_rule` into the same `"unknown"` severity default it already uses for a genuinely-deleted rule. Treat those specific views/fields as unknown, not "confirmed absent", while the counter is moving; a sustained rate still means that surface is failing. Pre-seeded to 0 for both sources × all three reasons at boot. Alert `YuzuGuardianReadDegraded` (`sum(rate(...[5m])) by (reason, source) > 0`, `docs/prometheus/yuzu-alerts.yml`) fires on either source; treat a zero DEX panel under a firing `guardian_state` window as "unknown", not "healthy". **Named exception (#4855):** a degrade counted here for the per-device DEX experience-score read (`dex_device_signal_summary`) does NOT read as empty/healthy — that one read fails closed (degraded lens placeholder / REST `503` / MCP retryable error, never a fabricated score). See the "DEX reads degrade to empty, not error" note in [guaranteed-state.md](guaranteed-state.md), "4. Push to agents". |
| `yuzu_fleet_agents_dex_observer_disarmed` | gauge | Windows agents (DEX enabled) whose DEX signal observer is not currently healthy — it failed to arm at startup, or a channel subscription died at runtime (EventLog restart / channel ACL change). `> 0` means reliability telemetry is off or degraded on that many endpoints. Agents off Windows or started with `--dex-disable` are excluded, so this is a genuine fault count. Rolled up from agent heartbeats. Note: it does **not** detect a host where the underlying reporter is disabled (e.g. Windows Error Reporting off → no Event 1000, observer still armed). |
| `yuzu_fleet_dex_observed_total` | gauge | Fleet-wide sum of DEX signals observed (all obs_types) since each agent started. **A gauge, not a monotonic counter** — it resets when an agent restarts, so do not apply `rate()`/`increase()`; per-signal detail lives in the Guardian events store (`GET /api/v1/guaranteed-state/events?rule_id=__observation__`) and the `/dex` dashboard. |
| `yuzu_server_guardian_proj_failures_total` | counter | DEX observation projection failures. The source event is always preserved (degrade-don't-destroy); only the derived read-model row is lost. `> 0` means `/dex` is under-counting — investigate (commonly a stale-schema dev DB). |
| `yuzu_server_guardian_observations_reaped_total` | counter | Cumulative DEX observation rows deleted by the retention reaper (disposal evidence for the behavioral-PII projection). Exposed as TYPE `counter` (store-read value set via the gauge API, like `events_written_total`). |
| `yuzu_server_guardian_platform_matrix_stale_total{spark_type}` | counter | #4252: fires when a Guardian **dashboard** fragment render — the `/guardian` fleet view or a Baseline detail page (`GET /fragments/guardian/status`, `GET /fragments/guardian/baseline/{id}/page`) — finds an (agent, rule) pair the server's static guard-type/platform support matrix (`guardian::guardian_guard_supported_on_platform`) says cannot arm, but the agent already reported REAL status for that exact pair — i.e. the hardcoded matrix disagrees with what the agent has actually observed, and the pair is excluded from the synthetic "not implemented" fold rather than being double-counted. **Never** the REST/MCP `GET /api/v1/guaranteed-state/status` endpoint, which excludes this fold entirely (see [guaranteed-state.md](guaranteed-state.md)'s Compliance overview) — the two are distinctly-named surfaces despite the shared "status" word. `spark_type` is the closed set `registry-change`\|`file-change`\|`service-status-change`\|`unknown`, pre-seeded to 0 at startup; any other authored token folds to `unknown` rather than minting its own series. **Render-time only** — it fires when an operator loads a fragment, not on a continuous background sweep, so absence does not mean the condition never occurred, only that nobody has loaded the page since. `> 0` means the matrix needs a code change to catch up with reality (e.g. a new guard type ships agent-side support before this file is updated); it is not itself a defect once fixed. **No dedicated alert rule** — this is a diagnostic, check-on-incident signal (matching sibling counters `yuzu_server_guardian_proj_failures_total`/`yuzu_server_guardian_observations_reaped_total`), not a page-worthy one; there is also no runtime lever to silence it while a matrix fix is pending — the only recovery path is a server code change + redeploy. Not fired on the guard detail page, which was already pair-deduped before #4252 and was never at risk of the double-count. |

Broader Guardian metrics — rule push counts, agent apply latency, parse errors, and a fleet compliance-state distribution (compliant/drifted/error/unknown) — are on the roadmap alongside agent-side enforcement metrics.

### Guardian journal fleet gauges

Published on every fleet-health sweep (~15 s), fed from the
`yuzu.guardian_journal_*` heartbeat tags. These roll the **durable lifecycle-audit
journal**'s per-agent integrity counters up fleet-wide, so a lost Guardian lifecycle
record is visible on `/metrics` (and to any evidence automation that scrapes it)
instead of only in
one endpoint's heartbeat.

**All series are unlabelled.** Unlike `yuzu_fleet_net_*` / `yuzu_fleet_spark_*`, there
is no `os` or `stat` split: these are integrity and loss signals, where the fleet
question is *"did any endpoint lose a lifecycle record"* - a flat sum answers that and
a percentile obscures it. One consequence worth having: no agent-controlled label
means no cardinality exposure at all.

**What absence means, mechanically.** For the **counter families**, the agent emits a
journal tag **only when the counter is non-zero**, and every family is cleared and
re-published each sweep. So an absent family means: *no retained agent's latest
heartbeat carried a value for it that passed the forged-value parse.* (The three
`_seconds_max` age gauges at the end of the table have their own emission posture -
see their rows; the cleared-and-republished-per-sweep rule applies to them too.) Both edges matter and both are pinned by tests - a
non-conforming agent's explicit `"0"` parses and **publishes** the family at `0`, while
a rejected non-zero value (over the plausibility ceiling, say) leaves it **absent** and
increments `_tag_rejected`. What the rollup avoids is publishing a fabricated `0` for a
family nobody reported, which would read as "checked, nothing lost" when nothing was
checked.

This page deliberately stops there. It tells you what each gauge counts and when it is
emitted, not what a reading proves about fleet health - the interpretation belongs with
whoever enables alerting at the `prefer_spark` cutover, against a live journal.

**The counter rows are `gauge`-typed fleet sums, and they are monitor-only.** No
churn-robust *new-increment* alert exists over an unlabelled fleet sum of per-agent
cumulative counters: the sum cannot tell a new increment from a returning agent. The
full analysis - why `increase()`/`rate()`, `delta()` and bare `> 0` each fail, what the
rising-edge template does and does not buy, and the enable-time prerequisites - is
stated once, in the `yuzu-guardian-journal` preamble in `docs/prometheus/yuzu-alerts.yml`,
alongside the disabled templates themselves. Graph these, review them after an incident,
do not page on them. **The three `_seconds_max` age rows are structurally different**:
a fleet MAX of live ages with a meaningful absolute threshold, where a plain `> X for: Y`
IS sound (see the commented staleness examples in the same alerts file) - do not apply
the counter family's monitor-only reasoning to them wholesale, and equally do not apply
an "any journal series > 0" panel to the family, since ~30 s is a *healthy* staleness
reading.

**Two meta-signals are the exception.** `yuzu_fleet_guardian_journal_reporting` and
`..._tag_rejected` are server-owned counts published on **every completed sweep,
including at `0`**, unlike the 32. Two consequences, and the second is easy to miss:

- `_reporting == 0` while `yuzu_fleet_agents_healthy > 0` narrows the pipeline-dark
  question - but only once Guardian is actually deployed, since the sparse writer means
  `0` also covers "nothing has been journalled anywhere since restart".
- Because they are never cleared, the registry retains their last value indefinitely, so
  **neither their absence nor a `0` detects a stalled sweep** - a stall freezes the
  previous sample in place. Use `yuzu_server_reaper_sweep_duration_seconds` for sweep
  liveness.

**Two caveats that apply however you consume these.** An agent ageing out of the 90 s
staleness window drops its counters from the fleet sum without the underlying loss having
healed. After a server restart the series rebuild as agents heartbeat back in, which takes
longer than one sweep (the sweep is 15 s; the agent heartbeat interval defaults to 30 s). Treat the metric
as a signal and the audit trail as the evidence.

**Known limitations - read before citing these as assurance.** The signal is
*self-reported by the endpoint whose audit trail is in question*. Fabrication is
possible (a forged plausible value from an enrolled agent sets the gauge) and so is
suppression (an agent that simply stops emitting is indistinguishable from a healthy
quiet one). The series are unlabelled, so a raised value cannot name the affected
endpoints, and no operator surface exposes per-agent `yuzu.guardian_journal_*` tags
today - building one is a prerequisite for enabling any alert here. Treat this as a
best-effort compensating indicator, not independent evidence of audit-trail
completeness.

**Timing after cutover.** The journal keeps 7 days of batches, so the eviction counters
(`_evicted_*`) are structurally silent for roughly the first week after `prefer_spark`
flips - absence in that window is guaranteed rather than evidentiary. After it, a mass
reboot or OTA can produce a large step in `_evicted_no_send_evidence` about a retention
window later that is population churn, not a new incident.

> **Selector caveat.** Five counters in this family break the `yuzu_fleet_guardian_journal_*`
> naming pattern - `yuzu_fleet_guardian_send_exceptions`, `yuzu_fleet_guardian_send_orphan_exceptions`,
> `yuzu_fleet_guardian_send_stalls`, `yuzu_fleet_guardian_drain_exceptions`, and
> `yuzu_fleet_guardian_sweep_exceptions` (their wire tags likewise drop the `_journal_`
> infix, sitting beside `drain_exceptions`). A PromQL selector like
> `{__name__=~"^yuzu_fleet_guardian_journal_"}` silently omits all five. Match
> `^yuzu_fleet_guardian_` if you mean the whole family - and note that EITHER selector
> now also sweeps in the three `_seconds_max` age gauges, which are MAX-rolled live ages
> (not sums of counters): exclude `_seconds_max$` from any panel or rule that assumes
> "non-zero means something was lost".

| Metric | Type | Description |
|---|---|---|
| `yuzu_fleet_guardian_journal_stage_dropped` | gauge | Fleet sum of records dropped at staging - the pending reserve overflowed. A **loss** channel - these records never reached the journal. THREE causes, and they need different responses: sustained write failure (see `_write_failures`); capacity refusal (see `_write_capacity_rejected`); and, since #2299, simply out-running the heartbeat's per-tick persist bounds - up to 4 batches / 1024 records per tick, which in the byte-split regime is the lower figure by far. On that third path `_write_failures` and `_write_capacity_rejected` are both **zero** and nothing is broken; compare `_batches_written`'s rate against the per-tick ceiling before concluding the alert is faulty. Monitor-only |
| `yuzu_fleet_guardian_journal_stage_failures` | gauge | Fleet sum of disarm records that could not be built post-teardown. A **loss** channel: the lifecycle end of a rule is unrecorded |
| `yuzu_fleet_guardian_journal_field_rejected` | gauge | Fleet sum of records kept out by a field failing validation (embedded NUL, oversized, non-UTF-8). A **loss** channel and a malformed-input signal |
| `yuzu_fleet_guardian_journal_clock_rejected` | gauge | Fleet sum of records kept out by a skewed clock (timestamp ≤ 0). A **loss** channel, and the fleet's clock-health canary - a journal timestamp that cannot be trusted is not admissible evidence |
| `yuzu_fleet_guardian_journal_pending` | gauge | Fleet sum of records staged but **not yet persisted**. A **live depth** gauge *per agent* - it drains as the backlog clears - but what is published is the fleet **sum**, which at 10k agents is non-zero essentially always, so `> 0` fires permanently on a healthy fleet and is **not** a valid alert. Monitor-only, like the rest of the family. Sustained depth is the leading indicator of the `_stage_dropped` loss that follows when the reserve overflows |
| `yuzu_fleet_guardian_journal_batches_written` | gauge | Fleet sum of batches successfully persisted. A cumulative process-lifetime count: non-zero means that agent's journal has persisted at least one batch since it last restarted. It resets to 0 on agent restart, and a journal whose every write fails never sets it, so do not read it as liveness. Unit is **batches** of up to 256 records |
| `yuzu_fleet_guardian_journal_write_failures` | gauge | Fleet sum of failed batch writes. Records stay staged and retry, so this is not itself loss - sustained failure fills the pending reserve, after which staging overflow increments `_stage_dropped`. It leads `_stage_dropped` **on that path only**: `_field_rejected` and `_clock_rejected` move without it, and the capacity-refusal path can reach `_stage_dropped` without a single write failure |
| `yuzu_fleet_guardian_journal_key_collisions` | gauge | Fleet sum of batch key collisions. Should stay 0; any value is an accounting or id-generation bug surfacing - investigate, do not threshold |
| `yuzu_fleet_guardian_journal_quarantined` | gauge | Fleet sum of batches moved aside as unreadable/corrupt. Degrade-don't-destroy: the batch is preserved for forensics but its records are **not** replayed, so `> 0` means the server is missing lifecycle evidence that still exists on the endpoint. Unit is **batches** of up to 256 records |
| `yuzu_fleet_guardian_journal_quarantine_failures` | gauge | Fleet sum of quarantine attempts that themselves failed - strictly worse than `_quarantined`: the corrupt batch could not even be set aside, so it may be re-hit every maintenance tick |
| `yuzu_fleet_guardian_journal_quarantine_capacity_evicted` | gauge | Fleet sum of quarantined batches shed at the quarantine cap. **Terminal loss** - forensic evidence that had been preserved is now gone. Unit is **batches** of up to 256 records |
| `yuzu_fleet_guardian_journal_pruned` | gauge | Fleet sum of batches deleted by retention (routine disposal evidence). Expected non-zero on a working fleet; read it as **activity context** for the failure counters beside it, not as a denominator and not as an alert. Unit is **batches** of up to 256 records |
| `yuzu_fleet_guardian_journal_prune_failures` | gauge | Fleet sum of retention prune failures. Retention not running means the journal grows toward its byte/count cap, where new writes start being refused - see `_write_capacity_rejected` |
| `yuzu_fleet_guardian_journal_write_capacity_rejected` | gauge | Fleet sum of new batches **refused** because the journal is at its byte/count cap. **Not itself loss**: the refused batch stays staged and the maintenance tick retries it once a later prune frees capacity. Records are lost only if staging then overflows - see `_stage_dropped`. Unit is **batches** of up to 256 records |
| `yuzu_fleet_guardian_journal_gauge_underflow` | gauge | Fleet sum of times an agent's write-ceiling check read the journal size gauge as **negative** (UP-2 / #2303). Correct operation never underflows, so **any non-zero is a real size-accounting bug** on that endpoint: persist then fails **closed** (defers to RAM staging) until a prune rebase restores the gauge. Matters because `_batch_count` **clamps a negative to 0** - the endpoint reads as a healthy empty journal while refusing writes, so this is the only signal that de-camouflages that state |
| `yuzu_fleet_guardian_journal_bytes` | gauge | Fleet sum of live on-disk journal size in bytes. A **live** gauge. Capacity signal - a value climbing toward (agents × per-endpoint cap) predicts `_write_capacity_rejected` |
| `yuzu_fleet_guardian_journal_batch_count` | gauge | Fleet sum of live batch count. A **live** gauge - the count-cap twin of `_bytes`; either ceiling alone can start refusing writes |
| `yuzu_fleet_guardian_journal_pages` | gauge | Fleet sum of replay paging passes. Activity, not health - the denominator that tells you replay is running at all |
| `yuzu_fleet_guardian_journal_records_paged` | gauge | Fleet sum of journalled records newly enqueued into the replay window. Activity signal for how much backlog is being re-delivered |
| `yuzu_fleet_guardian_journal_sent_labels` | gauge | Fleet sum of sent-labels written, in **batches** (best-effort delivery evidence). **Not** a valid denominator for the eviction counters despite the matching unit: labels are counted in the current agent process, while evictions cover batches written up to 7 days earlier across a churning fleet, so after a restart the numerator can exceed it. Read as activity, never as a rate base |
| `yuzu_fleet_guardian_journal_evicted_sent_unacked` | gauge | Fleet sum of **batches** aged out of the journal **with** a sent-label but no ack (each batch holds up to 256 records). **Monitor, do not page**: their records were sent and are very likely stored server-side; only the ack did not come back. Read against its no-evidence sibling |
| `yuzu_fleet_guardian_journal_evicted_no_send_evidence` | gauge | Fleet sum of **batches** aged out with **no** sent-label - no evidence their records were ever transmitted (each batch holds up to 256 records, so this understates the record count). This is the **integrity-gap** counter: `> 0` suggests lifecycle audit records were lost between endpoint and server. A CC7.3-relevant evidence signal. Treat a rise as a **ticket to investigate**, not an incident-register entry: classification is **best-effort** (a crash between the send and the sent-label write counts a sent batch as no-evidence), so a mass reboot or OTA manufactures a large benign step about a retention window later. Do not escalate until agent-side corroboration or magnitude analysis rules out that artifact class. Monitor-only. Since #2299 also cross-check `yuzu_fleet_guardian_journal_quarantined`: corrupt-VALUE quarantine moved to the replay pass, so a corrupt batch the rotation never reaches before it ages out is counted here instead - both are lost evidence, but this no longer separates "never delivered" from "never deliverable". |
| `yuzu_fleet_guardian_journal_evicted_unclassified` | gauge | Fleet sum of **batches** aged out whose sent/unsent disposition was **permanently unknown** - the third, mutually-exclusive eviction outcome. It exists for accounting exactness: `pruned == evicted_sent_unacked + evicted_no_send_evidence + evicted_unclassified` every pass, which is what lets `_evicted_no_send_evidence` be read as a trustworthy **floor** on lost evidence rather than a value a mid-pass shutdown could silently shrink. **Neither loss nor success.** Three causes: a stop landing **before classification begins** (right after the delete, before the sent-label scan) counts the whole evict set here - at most **once** per process lifetime, since the stop latches (since #2470 a stop landing DURING scan-OK classification no longer counts here: the determinable remainder is classified from the already-materialized scan; only a stop mid-**fallback** loop, where the scan already failed, still truncates its remainder to unknown); an **unreadable** sent-label on the scan-failure fallback (paired with a same-pass `_prune_failures` increment - a repeated climber, unlike the single shutdown bump); and a mid-classification `bad_alloc`, whose remainder lands here while the throw itself is counted as `_maint_exceptions`. Monitor-only. Unit is **batches** of up to 256 records |
| `yuzu_fleet_guardian_journal_maint_exceptions` | gauge | Fleet sum of exceptions swallowed by the journal maintenance tick (page/flush). Swallowed so maintenance cannot kill the agent - which is exactly why they must be visible here: a climbing value means maintenance is failing silently and the counters beside it are **understating** reality |
| `yuzu_fleet_guardian_journal_backpressure_drops` | gauge | Fleet sum of lifecycle-audit entries **rejected** at outbox enqueue for capacity. A **loss** channel: arm/disarm still succeeds, but the audit record of it is dropped. A non-zero value means the audit trail is missing lifecycle edges under sustained delivery backpressure |
| `yuzu_fleet_guardian_send_exceptions` | gauge | Fleet sum of per-entry drain **sends** that threw. Finer-grained than `_drain_exceptions`: one entry couldn't be serialized/sent, so that log's drain stops and jams delivery behind it. Spans the lifecycle log and the general outbox. **Wire key `yuzu.guardian_send_exceptions` (no `_journal_` infix)** |
| `yuzu_fleet_guardian_drain_exceptions` | gauge | Fleet sum of firewalled throws in the outbox **delivery** machinery on the drain worker. Distinct from the journal counters: events are buffered but not shipping - a delivery fault, not a retention or audit-trail fault. **Wire key `yuzu.guardian_drain_exceptions` (no `_journal_` infix)** |
| `yuzu_fleet_guardian_sweep_exceptions` | gauge | Fleet sum of firewalled throws in the convergence **sweep** lanes. Drift detection is degraded (the endpoint may miss policy violations) while the audit trail itself is unaffected. **Wire key `yuzu.guardian_sweep_exceptions` (no `_journal_` infix)** |
| `yuzu_fleet_guardian_send_orphan_exceptions` | gauge | Fleet sum of outbox-send reclaims (either lane) whose orphaned worker's result was a thrown exception, **discarded** rather than attributed - the orphaned result belongs to a superseded entry with nowhere correct to attribute it, so the discard itself is correct; this is a diagnostic signal, not a loss channel. **Wire key `yuzu.guardian_send_orphan_exceptions` (no `_journal_` infix)** |
| `yuzu_fleet_guardian_send_stalls` | gauge | Fleet sum of outbox sends (either lane) that exceeded their stall threshold before completing or being reclaimed. A non-zero value means at least one endpoint's outbox delivery is running slow, not necessarily failing. **Wire key `yuzu.guardian_send_stalls` (no `_journal_` infix)** |
| `yuzu_fleet_guardian_journal_page_stale_seconds_max` | gauge | Fleet **MAX** (worst endpoint, `_max` suffix - not a sum like the rest of the family; two 30 s-stale agents are not one 60 s-stale agent) of seconds since the drain worker's last **replay-progressing or verified-idle** page pass, seeded from worker start. A **replay-progress** gauge (#2452): the drain worker advances it only on a pass that placed records OR ran a full candidate scan finding a clean, unblocked, uncorrupted, readable idle backlog (one positive `progress_or_verified_idle` signal, mirroring the prune side). So it grows without bound not only on a dead or permanently-throwing worker but on any page pass that cannot make progress - deferred for lack of a paging token, falling back on a failed sent-label scan, hitting a candidate/value read failure, unable to latch its boot-prune barrier (journal scan failing from boot), **blocked because the send window is saturated (headroom)**, or **quarantining every candidate on a mass-corruption endpoint** - so it reads as an ever-growing age whenever replay is genuinely stalled, not only when the loop is dead. A pass that placed records, or that positively established there was nothing to page, reads fresh (real progress is never treated as stale just because one candidate read failed). Unlike the counters, the wire tag is emitted every heartbeat **including `0`** while the worker is live, and is **absent entirely** while dormant (`prefer_spark` off). Expect it to hover around the 30 s page cadence on a healthy fleet |
| `yuzu_fleet_guardian_journal_prune_stale_seconds_max` | gauge | Fleet **MAX** of seconds since the drain worker's last prune pass that **actually ran retention** - applied the delete OR verified nothing was eligible - the prune sibling of `_page_stale_seconds_max`, separate because the cadences differ (120 s vs 30 s) and stall independently. A growing value means retention is not running on some endpoint - the loop is dead/throwing, its journal scan is failing every pass (`_prune_failures` climbing), **its retention DELETE is failing every pass** (disk-full / perms; also `_prune_failures`), a stop keeps aborting it before the delete, it keeps **declining age eviction of expired rows on a clock anomaly**, or it **cannot quarantine a stuck malformed key** (`_quarantine_failures`) - and the journal grows toward its cap, where writes start being refused (`_write_capacity_rejected`). (A forward-clock-jump wipe is the one case that still reads fresh here, since the delete did succeed - the clock guard, not this gauge, owns that.) Expect ~120 s on a healthy fleet. Same emit-including-`0` / absent-while-dormant posture as its page sibling |
| `yuzu_fleet_guardian_journal_headroom_blocked_seconds_max` | gauge | Fleet **MAX** of the age of the oldest current **headroom-blocked replay-congestion episode** (#2364): somewhere a journal batch could not be placed in the send window for lack of room, continuously since the value's start. Episode-scoped and sampled at pass granularity: clears only after a proven block-free sweep of all of that journal's *candidates* (the batches a replay pass currently considers - unexpired, unquarantined journal batches), resets on agent restart, and a forced (boot/reconnect) pass can start an episode from already-delivered batches - read it as **replay-window congestion**, not proof of unsent loss. Its loss-relevant threshold is the 7-day retention window (604 800 s): an episode approaching that means never-sent records on that endpoint are nearing deletion - read with `_evicted_no_send_evidence`. **Caveat**: a clear can *coincide* with the blocked batch's own terminal eviction (an evicted batch stops being a candidate, so coverage completes) - corroborate a clear against `_evicted_no_send_evidence` before reading it as recovery. **Sparse**: absent means no endpoint is blocked |
| `yuzu_fleet_guardian_journal_reporting` | gauge | Agents whose latest heartbeat carried at least one **parseable** journal tag - the coverage denominator the 32 counters lack. **Published every sweep including `0`**, unlike them. Read `0` carefully: the writer is sparse, so this counts agents with a **non-zero** counter, not agents whose journal works - `0` means either the telemetry path is dark **or** nothing has been journalled anywhere since restart (a live journal on a fleet with no deployed Guardian rules reads `0` legitimately). It narrows the overloaded absence of the 32; it does not resolve it. **Counts the 32 counter tags only - an agent reporting only the three `_seconds` age tags does not count here** |
| `yuzu_fleet_guardian_journal_tag_rejected` | gauge | Journal tags **present** on a heartbeat this sweep but rejected by the forged-value parse (non-numeric, negative, over 10 digits, or above the plausibility ceiling). **Published every sweep including `0`**. Without it a rejected value is a silent drop - if the rejecting agent were the only reporter, its family goes absent and absent reads as clean. `> 0` means some agent is shipping malformed journal telemetry |

### Guardian arm-ledger fleet gauges (rung 9c PR-3)

Published on every fleet-health sweep, fed from `yuzu.guardian_arm_pending` /
`yuzu.guardian_arm_failed`. Unlike the journal counters above, these are
**re-statable gauges** - each agent reports its CURRENT ack-ledger state
(`GuardianArmAckLedger::arm_stats()`), not a monotonic total - so the fleet gauge
is a SUM of current values, and it can legally decrease. Absent means no agent
reported this sweep, which today (`prefer_spark` off fleet-wide) means every
agent, by construction - a non-spark agent never emits this pair at all.

| Metric | Type | Description |
|---|---|---|
| `yuzu_fleet_guardian_arm_pending` | gauge | Fleet **SUM** of accepted spark arms currently pending acknowledgment (still awaiting a Committed/terminal resolution), across every agent's CURRENT application. Re-statable, not cumulative - decreases as receipts resolve or an application is replaced |
| `yuzu_fleet_guardian_arm_failed` | gauge | Fleet **SUM** of accepted spark arms whose CURRENT application resolved to a non-Committed terminal outcome (Failed/CongestionExpired/Wedged/Withdrawn/Stopped), still unresolved for acknowledgment. Resets to `0` the moment an application that saw a failure is REPLACED - an ordinary retry of that generation, live today - regardless of whether that retry itself succeeds; a rule that fails again climbs back up over the following ticks. Reflects same-application recovery for the **Wedged case only** (rung 9c PR-5d): a Wedged receipt whose late arm succeeds and is adopted (the rule was still desired) clears its own contribution here without waiting for a new application. Every other non-Committed status (Failed/CongestionExpired/Withdrawn/Stopped) still only clears via an application replacement, exactly as before. Zero does not itself mean compliant or enforced. **Alerting**: a `for:`-duration rule keyed on this gauge alone can be reset by the ~25 s retry cadence - prefer `arm_pending + arm_failed > 0` sustained. **K-bound caveat (rung 9c PR-5e, #4221):** do NOT use `yuzu_fleet_guardian_generation` catching up to the server's target as a proxy for "no longer failing" - after 3 identical re-applies of a persistently Wedged-only key (every OTHER outstanding failure in the application, if any, still holds the acknowledgment indefinitely regardless), the generation now ACKNOWLEDGES (catches up) while this gauge stays sustained nonzero for that same rule. **The "3" counts identical push re-applies, not this specific rule's own wedge observations** - it's a single shared counter per application-sequence, so a rule can be waived on the VERY FIRST time it's ever observed wedged if an unrelated sibling rule's own ordinary, now-cleared failure already funded the count on earlier re-applies (see `docs/spark-legacy-delta-registry.md` Row A3 for the full mechanism); `arm_failed` sustained nonzero is the durable signal for the CURRENT application (see this row's own "Resets to `0`" sentence above - a later, distinct push still zeroes it unconditionally, same as always; this is not a durable cross-application "still failing" gauge), generation lag is not a reliable alternative once K-waiver has fired |
| `yuzu_fleet_guardian_arm_reporting` | gauge | Agents whose latest heartbeat carried at least one parseable `yuzu.guardian_arm_*` tag - the coverage denominator for the two gauges above. **Published every sweep including `0`**. `0` means no agent currently has `prefer_spark` on AND live (not stopped, not Unwired/SparkFailed/SparkDisabled) AND a current application - the expected reading on every released fleet today, since `prefer_spark` is hardcoded false. **Do NOT cross-check `yuzu_fleet_spark_reporting`** to disambiguate "telemetry dark" - that gauge counts SparkEngine running observe-only, which is live fleet-wide independent of `prefer_spark`, so `spark_reporting > 0` with `arm_reporting == 0` is the NORMAL pre-cutover reading, not a dark-telemetry signal. If genuine dark-telemetry suspicion arises, check `yuzu.guardian_backend`/agent logs instead |
| `yuzu_fleet_guardian_arm_tag_rejected` | gauge | `yuzu.guardian_arm_*` tags **present** this sweep but rejected by the forged-value parse. **Published every sweep including `0`**. `> 0` means some agent is shipping malformed arm-ledger telemetry |

### Guardian io-ceiling fleet gauge (rung 9c PR-3, R5.1)

`GuardianIoExecutor`'s physical-orphan alive-worker ceiling (R5.1's own flagged
observability gap) gets one narrow, MONITOR-ONLY counter, scoped to the arm/disarm
executor instance only - **not** #3415's general per-class executor-fault egress,
which stays a separate, still-open follow-up (see the executor bulkhead docs in
[guaranteed-state.md](guaranteed-state.md) and `docs/spark-legacy-delta-registry.md`
row D10). A windowed "currently under repeated pressure" detector was considered for
this signal and deliberately DEFERRED to a later rung rather than shipping an
unmeasured threshold now - this counter names the fault class only.

| Metric | Type | Description |
|---|---|---|
| `yuzu_fleet_guardian_io_arm_disarm_rejected_ceiling` | gauge | Fleet **SUM** of admissions refused at the arm/disarm executor's per-instance physical alive-worker ceiling (workers still alive past `fn()` inside their completion callbacks while ordinary class quota was free). A genuinely cumulative per-agent counter - correctly MONITOR-ONLY: neither `increase()` nor a bare `> 0` is sound over a fleet sum of per-agent cumulative counters. Names the fault class; does not by itself say whether an endpoint is CURRENTLY wedged |
| `yuzu_fleet_guardian_io_ceiling_reporting` | gauge | Agents whose latest heartbeat carried the ceiling tag - the coverage denominator. **Published every sweep including `0`**. The writer is sparse (a zero ceiling count ships no tag), so `0` here means no currently-retained agent has hit the ceiling since its own process last started (or none is running spark) - counters reset on agent restart and this reads only the latest retained heartbeats, not durable history; not that telemetry is dark |
| `yuzu_fleet_guardian_io_ceiling_tag_rejected` | gauge | The ceiling tag **present** this sweep but rejected by the forged-value parse. **Published every sweep including `0`** |

### Guardian M1 health-stream fleet gauges

The M1 flood-guard telemetry ([Guaranteed State](guaranteed-state.md)'s errored-view
staleness/priority-lane backstops), the #2993 outbox-backpressure signal, and the
#4783 legacy-sink loss-visibility trio: 7 sparse counters rolled up as an
**unlabelled fleet sum**, same absent-not-zero rule and same forged-value posture as
the journal family above - a healthy fleet reads all seven **absent**, never a
fabricated `0`. An **inert** (`prefer_spark` off) fleet reads only the four M1/outbox
gauges absent - the three `_legacy_sink_*` gauges are **always live regardless of the
Spark flip** (the legacy `IGuard` sink is the current production detection path, see
the rows below) and CAN fire in that mode. **Monitor-only**, same reasons as the
journal family: no churn-robust alert form exists over an unlabelled fleet sum of
per-agent cumulative counters.

| Metric | Type | Description |
|---|---|---|
| `yuzu_fleet_guardian_unhealthy_suppressed` | gauge | Fleet sum of convergence re-evals of a still-errored Guardian rule whose repeat `guard.unhealthy` was **not** re-emitted (the edge-suppression flood guard). Monitor-only |
| `yuzu_fleet_guardian_unhealthy_refreshed` | gauge | Fleet sum of `guard.unhealthy` **re-emissions** for a rule still stuck errored, sent at `errored_refresh_ms` cadence (default 300 s) so a lost/coalesced edge cannot leave the server's errored view stale forever. Sibling to `_unhealthy_suppressed` - together they partition every committed repeat-errored eval into "put on the wire" vs "not this tick" |
| `yuzu_fleet_guardian_priority_demoted` | gauge | Fleet sum of rule_ids demoted off the 5 s convergence priority lane to their normal type-lane cadence after K consecutive Unknown sweeps or T elapsed (defaults 12 sweeps / 120 s) - the read-flood guard for a rule stuck pending-initial |
| `yuzu_fleet_guardian_outbox_backpressure_drops` | gauge | Fleet sum of compliance/health entries rejected at an agent's MAIN outbox capacity (#2993) - distinct from the journal family's own backpressure gauges above, a different log. A chronic per-agent jam here means compliance/health drift is being lost, not just delayed. Monitor-only |
| `yuzu_fleet_guardian_legacy_sink_events_lost` | gauge | Fleet sum of legacy Guardian sink events an agent could not deliver (#4783) - refused at the detached sender's queue capacity, an admission failure, a failed `Write()`, or a throwing send; excludes the pre-network-arm drop (its own gauge, `_dropped_unwired` below), the stop()-time backlog discard, and the link-down drop, which remain genuinely un-signaled outside the agent process (the pre-existing, un-built "durable buffering is A3" residual, `docs/spark-legacy-delta-registry.md`). Restart-durable per agent (#4783 Gate 4 UP-3): each agent persists its own counter to its own KvStore and restores it at boot, so a mid-outage agent restart does not reset that agent's own contribution back to 0 - the exported fleet sum above is still cleared/rebuilt every sweep like the rest of this family. Always live regardless of the Spark flip (`prefer_spark`) - the legacy IGuard sink is the current production detection path. Monitor-only |
| `yuzu_fleet_guardian_legacy_sink_gap_rules` | gauge | Fleet sum of rules with an OPEN sticky legacy-sink integrity gap (#4783) - a rule whose last drift/compliance report was lost and not yet confirmed repaired. The agent self-heals this every heartbeat by synthesizing a `guard.unhealthy` repair report per open gap; a persistently non-zero sum means repairs are also failing to deliver. Restart-durable per agent, same mechanism as `_events_lost` above (`docs/spark-legacy-delta-registry.md` D13). Monitor-only |
| `yuzu_fleet_guardian_legacy_sink_dropped_unwired` | gauge | Fleet sum of legacy Guardian sink events dropped because the event sink wasn't wired yet (#4783) - the guard fired before `agent.cpp`'s post-Subscribe `set_event_sink` call, a routine window on every agent boot. Unlike its two siblings above, this drop has **no gap-repair compensation** - a legacy guard only re-reports on its next real transition, so a nonzero value can mean genuine, still-unrecovered loss of already-committed guard state until that rule's compliance state changes again or the agent restarts. **NOT restart-durable** (unlike `_events_lost`/`_gap_rules` above) - it's a bare in-process counter, never persisted, so it resets to 0 across a restart with no record of what was lost. Always live regardless of the Spark flip. Monitor-only |
| `yuzu_fleet_guardian_health_reporting` | gauge | Agents whose latest heartbeat carried at least one **parseable** health tag - the coverage denominator for the 7 counters. **Published every sweep including `0`**. Read `0` carefully, same caveat as the journal family's reporting gauge: the writer is sparse, so this counts agents with a non-zero counter, not agents whose health pipeline is working - a live fleet with nothing currently errored/refreshed/demoted/backpressured/lost/gapped/dropped-unwired reads `0` legitimately |
| `yuzu_fleet_guardian_health_tag_rejected` | gauge | Health tags **present** on a heartbeat this sweep but rejected by the forged-value parse. **Published every sweep including `0`**. `> 0` means some agent is shipping malformed Guardian health telemetry |

`errored_rules` on `GET /api/v1/guaranteed-state/status` and `/status/{agent_id}`
(#2298 item 6d) is a **separate**, REST-surfaced count derived from the
`guardian_agent_rule_status` census table, not from these heartbeat gauges - the two
answer different questions (this family: how much flood-guard activity occurred;
`errored_rules`: how many rules are errored right now).

## NVD CVE sync metrics

The server maintains a local mirror of the NVD (National Vulnerability Database)
CVE catalog (see [NVD CVE sync](server-admin.md#nvd-cve-sync) for the sync flags).
These metrics surface the catalog's size, backfill progress, and sync-window
health. The gauges are refreshed on every `/metrics` scrape.

| Metric | Type | Description |
|---|---|---|
| `yuzu_nvd_total_cves` | gauge | Distinct CVEs in the local NVD catalog. Grows as the newest-first backfill walks history, then holds steady with periodic freshness re-checks. |
| `yuzu_nvd_backfill_complete` | gauge | `1` when the newest-first NVD backfill has reached its floor (`--nvd-backfill-years`), else `0`. `0` for an extended period on a fresh server without an API key is expected — the backfill is rate-limited (see below). |
| `yuzu_nvd_sync_failures_total{reason}` | counter | NVD sync window failures, labelled by `reason` ∈ {`connection`, `http_429`, `http_403`, `http_other`, `parse`}. All five `reason` series are initialised to `0` at startup, so the counter (and its HELP/TYPE) is present on a healthy server — `absent()`-style alerts stay meaningful and Grafana never shows "No data" until the first failure. A shutdown-triggered cancel is deliberately **not** counted. |

**Reading the `reason` label:** `http_429` is rate-limiting (backed off and retried
automatically — expected during a large backfill without an API key, not a fault);
`http_403` is a bad or revoked `--nvd-api-key` (not retried — rotate the key);
`connection` is an egress/network failure to `services.nvd.nist.gov`; `http_other`
is any other non-2xx status; `parse` is a malformed response body. See
[Rate-limit and auth-error handling](server-admin.md#nvd-cve-sync) for operator guidance.

**Alerting.** Only `http_403` is unambiguously operator-actionable, so page on it and
merely record the rest:

```
# Page: bad/revoked API key — sync makes no progress until rotated
increase(yuzu_nvd_sync_failures_total{reason="http_403"}[1h]) > 0
# Do NOT page on http_429 — it is expected rate-limiting, self-heals via backoff.
```

Note that `http_429` **will** climb during a first-run full backfill on a server with no
`--nvd-api-key` (each window that exhausts its retry budget increments it before the next
tick retries) — that is expected first-run behaviour, not a regression. A sustained
`yuzu_nvd_backfill_complete == 0` (see above) is the durable "mirror stuck" signal, not the
failures counter on its own. Under `--no-nvd-sync`/`YUZU_NO_NVD_SYNC`, `yuzu_nvd_backfill_complete`
is **absent** (never emitted), not `0` — an `absent()`-style alert built on this series should
account for the deliberately-disabled case, not just the stuck case.

## Management group metrics

The server exposes two gauges plus two counters for management group telemetry.
The gauges are refreshed on every `/metrics` scrape; the counters are cumulative.

| Metric | Type | Description |
|---|---|---|
| `yuzu_server_management_groups_total` | gauge | Total number of management groups (including the root "All Devices" group) |
| `yuzu_server_group_members_total` | gauge | Total membership records across all management groups |
| `yuzu_server_mgmt_group_read_degrade_total{reason}` | counter | A **confinement-feeding** hierarchy read (ancestors/descendants/agent-groups) or a **row-resolution** read (`get_group_checked` and/or `get_members_checked`, incl. the legacy `get_group()`/`get_members()` wrappers — #1762) degraded instead of returning a result. The hierarchy reads fail closed to **DenyAll**. Callers on the CHECKED twins surface the degrade as their own 503/retryable result rather than a healthy-looking empty/not-found: the DEX app-perf group trend (`LocalDexPerfApi::group_trend`), `/auto` VERIFY's before/after compare (`LocalVerifyApi::compare`), and the management-group detail surface — `GET /api/v1/management-groups/{id}` + MCP `get_management_group`, both now on `get_group_checked` for the group row (governance round-2) as well as `get_members_checked` for the member list. The remaining callers stay on the LEGACY fail-soft `get_group()`/`get_members()` wrappers as KNOWN, DISCLOSED residuals (#4907) — NOT uniformly render-only: the dashboard scope-picker fragment genuinely is render-only, but `PolicyEvaluator::resolve_targets`, `dispatch_scope_ladder.hpp`'s `group_members_fn` closure, `command_routes.cpp`'s `/api/command` group-dispatch resolution, the `PreflightRoutes` group-cohort resolver, and the Guardian `group:`-scope rule-push resolution are all dispatch-TARGETING — a degrade there under-reaches to zero/fewer targets (fails safe) rather than mis-authorizing anyone, but is not "render-only". `reason` ∈ `store_not_open` (store failed to open at boot), `pool_acquire_timeout` (no Postgres connection available in time — correlates with `yuzu_pg_acquire_*` saturation), `query_error` (the query failed). **A non-zero rate means scoped operators, or an app-perf/VERIFY/management-group-detail read, see reduced/empty/degraded/retryable results** because the confinement substrate (`management_group_store`, ADR-0042) is degraded — it does **not** mean groups shrank. This is the deny-set fail-**open** hazard now closed (a degraded read denies or surfaces rather than silently under-restricting or rendering as empty). |

`yuzu_server_mgmt_group_backfill_total{result}` (the one-time SQLite→Postgres confinement
backfill outcome) was retired along with `ManagementGroupStore::migrate_from_sqlite()` itself
(chore/retire-migrate-from-sqlite-batch-a, #3623) — no production fleet ever ran a pre-Postgres
build, so there was no real `management-groups.db` data to migrate. See ADR-0042's Update.

**Example output:**

```
# HELP yuzu_server_management_groups_total Total number of management groups
# TYPE yuzu_server_management_groups_total gauge
yuzu_server_management_groups_total 5

# HELP yuzu_server_group_members_total Total members across all management groups
# TYPE yuzu_server_group_members_total gauge
yuzu_server_group_members_total 42
```

**Useful PromQL queries:**

```promql
# Total management groups
yuzu_server_management_groups_total

# Average members per group
yuzu_server_group_members_total / yuzu_server_management_groups_total

# Alert if no management groups exist (store may be down)
yuzu_server_management_groups_total == 0

# Confinement reads degrading → scoped operators see reduced/empty lists (DenyAll).
# A degrade denies confinement reads fleet-wide — treat any non-zero rate as a
# confidentiality/availability signal, not a fleet-size change. (Shipped as the
# YuzuMgmtGroupReadDegraded alert.)
sum(rate(yuzu_server_mgmt_group_read_degrade_total[5m])) by (reason) > 0
```

## Custom properties metrics (ADR-0045)

The `CustomPropertiesStore` — operator-authored per-agent metadata (schema
`custom_properties_store`) usable in scope expressions via `props.<key>` — is a migrated
PostgreSQL store (authoritative posture).

| Metric | Type | Description |
|---|---|---|
| `yuzu_server_custom_properties_read_degrade_total{reason}` | counter | A `props.<key>` scope-feeding read (the bulk `get_values_for_keys` preload `AgentRegistry::evaluate_scope` uses, or a direct property read) degraded instead of returning a result. `reason` ∈ `store_not_open` (store failed to open at boot), `pool_acquire_timeout` (no Postgres connection available in time — correlates with `yuzu_pg_acquire_*` saturation), `query_error` (the query failed). **A non-zero rate means a `props.<key>`-scoped dispatch/policy/push rule is aborting scope evaluation** — every caller collapses that abort to "zero targets matched," so this is NOT the same as "operators removed the properties." |

`yuzu_server_custom_properties_backfill_total{result}` (the one-time SQLite→Postgres backfill
outcome) was retired along with `migrate_from_sqlite()` itself
(chore/retire-migrate-from-sqlite-batch-b, #3623) — no production fleet ever ran a pre-Postgres
build, so there was no real `custom-properties.db` data to migrate. See ADR-0045's Update.

## Notification store (dashboard feed, ADR-0046)

`yuzu_server_notification_backfill_total{result}` (the one-time legacy backfill outcome)
was retired along with `migrate_from_sqlite()` itself
(chore/retire-migrate-from-sqlite-batch-b, #3623) — no production fleet ever ran a
pre-Postgres build, so there was no real `notifications.db` data to migrate. This store
had no other dedicated metric (`set_metrics()`/the `metrics_` pointer were retired with
it — nothing else consumed them). See ADR-0046's Update.

**Useful PromQL queries:**

```promql
# props.<key> scope reads degrading → scoped dispatch/policy/push rules may be
# silently matching nobody. (Shipped as the YuzuCustomPropertiesReadDegraded alert.)
sum(rate(yuzu_server_custom_properties_read_degrade_total[5m])) by (reason) > 0
```

## Analytics event outbox metrics (ADR-0049)

| Metric | Type | Description |
|---|---|---|
| `yuzu_server_analytics_emit_dropped_total{reason}` | counter | `AnalyticsEventStore::emit()` drops (fail-soft ingest — a dropped event never fails the request that emitted it). `reason` ∈ `store_not_open`, `pool_acquire_timeout`, `query_error`, `serialize_error`. All four series pre-seeded to `0` at startup. |
| `yuzu_server_analytics_read_degrade_total{method,reason}` | counter | `/api/analytics/status`/`/api/analytics/recent` reads that returned a degrade (`503`) rather than a result. `method` ∈ `query_recent`, `pending_count`; `reason` ∈ `store_not_open`, `pool_acquire_timeout`, `query_error`. All six combinations pre-seeded to `0`. |
| `yuzu_server_analytics_drain_pass_failed_total` | counter | Drain passes that threw an exception at the thread boundary and were abandoned (retried at the next interval, never crashes the server). |
| `yuzu_server_analytics_drain_last_pass_unixtime` | gauge | Wall-clock reading stamped at the start of every drain pass attempt, success or failure. **Caveat before alerting on staleness**: this gauge stays flat at its pre-seeded `0` for TWO distinct reasons, not one — (a) no sink is configured (`--analytics-jsonl`/`--clickhouse-url` both unset, the default install), or (b) the store failed to open at boot (`is_open()==false`) — the family is still registered either way, but the drain loop never started in either case. A staleness alert on this gauge needs the same never-started/not-running/metric-missing split the audit-retention family uses (`YuzuAuditRetentionNotRunning`/`..._NeverRan`/`..._MetricMissing`), gated on whether a sink is actually configured AND the store opened — not yet shipped (tracked as a follow-up). |

Analytics collection itself is disabled entirely with `--no-analytics` — no store is constructed, and the four metric families above are not registered at all (absent from `/metrics`, not present-at-zero; `absent()`-based alerting distinguishes this correctly from the degraded-but-registered case). See [Upgrading](upgrading.md) for the Postgres-cutover behavior change and ADR-0049 for the store's fail-soft/degrade-distinguishable posture.

## Tag store metrics (device tags / scope-targeting substrate, ADR-0050)

| Metric | Type | Description |
|---|---|---|
| `yuzu_server_tag_store_read_degrade_total{reason}` | counter | A tag read degraded instead of answering, and the caller FAILED CLOSED (ADR-0050): `tag:<key>` scope resolution aborts the whole evaluation (a tag-scoped dispatch reaches zero agents), service-scoped-token confinement 503s, and the REST/MCP tag surfaces answer `503`/`-32603` — never a silently-empty result. `reason` ∈ `store_not_open` (store failed to open at boot), `pool_acquire_timeout` (no Postgres connection in time — correlates with `yuzu_pg_acquire_*`/`yuzu_pg_pool_waiters` saturation), `query_error`. **A non-zero rate also means the policy evaluator is silently skipping `tag:`-scoped checks** (its tick collapses the abort to "no targets"; `PolicyStore.last_check_at` stops advancing). Pre-seeded to 0 for all three reasons. Write-path failures (set/sync/delete) are log-only — deliberately no per-store write counter (wave-level decision pending). |

`yuzu_server_tag_store_backfill_total{result}` (the one-time `tags.db` → Postgres
backfill outcome) was retired along with `migrate_from_sqlite()` itself
(chore/retire-migrate-from-sqlite-batch-b, #3623) — no production fleet ever ran a
pre-Postgres build, so there was no real `tags.db` data to migrate. See ADR-0050's
Update.

**Useful PromQL queries:**

```promql
# Tag reads degrading → tag-scoped dispatch failing closed to zero agents and
# policy tag-checks silently skipping. (Shipped as YuzuTagStoreReadDegraded.)
sum(rate(yuzu_server_tag_store_read_degrade_total[5m])) by (reason) > 0
```

## Product pack store metrics (operator-installed content, ADR-0054)

| Metric | Type | Description |
|---|---|---|
| `yuzu_server_product_pack_read_degrade_total{reason}` | counter | A `product_pack_store` read (`list()`/`get()`, including the per-pack item fetch) degraded instead of answering, and the caller FAILED CLOSED — `GET /api/product-packs`/`GET /api/product-packs/{id}` answer `503`, never a silently-empty pack list or a false "not found". `reason` ∈ `store_not_open` (store failed to open at boot), `pool_acquire_timeout` (no Postgres connection in time — correlates with `yuzu_pg_acquire_*`/`yuzu_pg_pool_waiters` saturation), `query_error` (covers both the pack-row query and the per-pack item-row query). Pre-seeded to 0 for all three reasons. `uninstall` write-path failures are still log-only — no per-store write counter (wave-level decision pending, matches `TagStore`'s own boundary) — but `install` gained one below (#3481). |
| `yuzu_server_product_pack_install_compensation_total{result}` | counter | Fires only when `install()`'s final Postgres persist (or its pre-persist duplicate-item-id check) fails AFTER `install_fn` already committed one or more items into sibling stores (#3481). `result` ∈ `ok` (every already-installed item was successfully compensated/undone) or `partial` — two distinct shapes share this label: at least one item's compensation itself failed (including a `compensate_fn` call that threw — see the paired `spdlog::error` line naming the exact kind/item id), OR (#3481, gov Gate 5 CHAOS-1b) the transaction's own outcome could not be confirmed at all (still in progress, or the confirmation check itself failed) — this second shape skips compensation ENTIRELY (zero items attempted, not just some), carries no per-item kind/item-id log line and no `(compensated N/M)` suffix on the audit `detail` (there is nothing to name — compensation never ran), and is the WORST-CASE residual since no cleanup was attempted at all. **The two shapes need DIFFERENT manual/operator responses — read the paired `spdlog::error` line first to tell them apart** ("compensation FAILED for `<kind>` '`<item_id>`'..." vs. "outcome could not be confirmed..."). Pre-seeded to 0 for both `result` values at boot, same as the two counters above — load-bearing here, not just convention: `increase()` needs a baseline (differently-valued) sample inside its window to detect a 0→1 step, so a series that only comes into existence already at 1 never fires (verified with `promtool test rules`). Alert on ANY occurrence of a non-zero `partial` count (`YuzuProductPackCompensationPartial`, `for: 0m` — deliberately not a sustained-rate threshold) — it means residual orphaned sibling-store content that self-heal cannot fix; a lone event is an operator cleanup task, not an incident, but it does not self-clear either. Remediation: if the paired log line names a specific kind/item id ("compensation FAILED for..."), that item is a confirmed orphan — delete it directly through that sibling store's own route (`DELETE /api/instructions/{id}`, `DELETE /api/policies/{id}` or `/api/policy-fragments/{id}`, `DELETE /api/workflows/{id}`). If it instead says "outcome could not be confirmed" (no item named — the ambiguous-outcome shape), do **NOT** delete anything by guessing item ids from the submitted bundle: first confirm via `GET /api/product-packs/{id}` whether the pack actually committed — a live, successfully-installed pack is indistinguishable from an orphan using this alert alone, and deleting a live pack's content is the exact destructive hazard the ambiguous-commit-outcome check exists to prevent. There is no bulk reconciliation sweep for either shape. **After a flap that produces several events at once** (gov Gate 6, sre): there is no batch tooling — enumerate candidates by correlating the counter's increment timestamps against `product_pack.install`/`product_pack.uninstall` audit rows carrying a `(compensated N/M item(s))` or "outcome could not be confirmed" detail in the same window, then loop the per-event remediation above for each. **Crash-mid-compensation blind spot:** this counter, its paired log line, and the audit row are all written only after the compensation loop completes — a process crash/restart during that loop leaves NO evidence on any of the three channels for that specific attempt. A restart around the time of a large pack install, with no alert or log line for it, is not proof compensation ran cleanly; check the submitted bundle against sibling-store content manually in that window (see `product_pack_store.hpp`'s F031 update note). |

**Useful PromQL queries:**

```promql
# Product-pack reads degrading → GET /api/product-packs* failing closed to 503.
# (Shipped as YuzuProductPackReadDegraded.)
sum(rate(yuzu_server_product_pack_read_degrade_total[5m])) by (reason) > 0
```

`yuzu_server_product_pack_backfill_total{result}` (the one-time legacy backfill outcome)
was retired along with `migrate_from_sqlite()` itself
(chore/retire-migrate-from-sqlite-batch-b, #3623) — no production fleet ever ran a
pre-Postgres build, so there was no real `product-packs.db` data to migrate. See
ADR-0054's Update.

## Instruction store metrics (content-plane catalog, ADR-0058)

The `InstructionStore` (`InstructionDefinition -> InstructionSet -> ProductPack`, schema
`instruction_store`) is a migrated PostgreSQL store (authoritative posture). It has **no
legacy-SQLite backfill** (ADR-0009's fresh-start-by-default class) — there is no
`*_backfill_total` family for it, unlike most stores on this page.

| Metric | Type | Description |
|---|---|---|
| `yuzu_server_instruction_read_degrade_total{reason}` | counter | An `InstructionStore` read degraded instead of answering, and the caller FAILED CLOSED — the REST/MCP surfaces answer `503`, never a silently-empty or silently-truncated catalog. `reason` ∈ `store_not_open`, `pool_acquire_timeout`, `query_error`. Pre-seeded to 0 for all three. |
| `yuzu_server_instruction_write_degrade_total{reason}` | counter | An `InstructionStore` write degraded instead of succeeding. `reason` ∈ `insert_definition_row`, `update_definition`, `delete_definition`, `insert_set_row`, `delete_set`. Pre-seeded to 0 for all five. Shared with the boot-time reseed loop's own inserts (`insert_definition_row`/`insert_set_row`) — a spike here during a boot window overlaps with `yuzu_server_instruction_bundled_content_total{result="errored"}` below; outside a boot window it's an ordinary operator-write failure. |
| `yuzu_server_instruction_bundled_content_total{result}` | counter | Outcome of the **every-boot** bundled-content reseed loop (`kBundledDefinitions`/`kBundledSets`, 232 definitions / 10 sets as of this writing) — distinct from the `*_backfill_total` one-time-at-boot shape used elsewhere on this page, since this store reseeds on **every** boot, not once. `result` ∈ `clean` (zero import errors) or `errored` (at least one definition/set failed to import against an open store). Pre-seeded to 0 for both. **`errored` means the boot refused to start** (gov Gate 4 UP-4/Gate 8 fix): a genuine DB error during the reseed loop sets `startup_failed_`, so — same caveat as the `*_backfill_total{result="failed"}` families elsewhere on this page — a refused boot never serves `/metrics`, making `errored` itself effectively unscrapeable; alert on the ABSENCE of `clean` instead, the same absent-success shape the `*_backfill_total` alerts elsewhere on this page use. |

**Useful PromQL queries:**

```promql
# InstructionStore reads degrading → REST/MCP catalog reads failing closed to 503.
sum(rate(yuzu_server_instruction_read_degrade_total[5m])) by (reason) > 0

# No server reporting a clean bundled-content reseed this boot → the reseed loop hit a
# genuine DB error and the boot refused to start (absent-clean shape, not
# result="errored" — a refused boot never serves /metrics).
absent_over_time(yuzu_server_instruction_bundled_content_total{result="clean"}[15m])
```

## Per-device concurrency enforcement metrics (ADR-1007)

`per-device` is the only concurrency mode with real enforcement (see `docs/user-manual/instructions.md`
§8) — a claim table (`execution_tracker.concurrency_claims`) excludes an agent already mid-execution
of the same definition from a repeat dispatch. All six metrics below are pre-seeded to 0 at server
construction except the liveness gauge, which is set unconditionally on every reconciler pass and
so needs no pre-seed (absent for at most one reconciler cadence — ~5 minutes — after boot).

| Metric | Type | Description |
|---|---|---|
| `yuzu_server_dispatch_concurrency_skipped_total` | counter | A `per-device` dispatch excluded one or more candidates because they already held an open concurrency claim for the same definition. The generic `POST /api/instructions/{id}/execute` 503 body points here when every named target was excluded this way. |
| `yuzu_server_concurrency_claim_unavailable_total` | counter | A claim attempt failed CLOSED (Postgres pool exhaustion or a query error) and excluded every candidate from that dispatch, independent of whether any were actually busy. Nonzero alongside the skip counter above points at store degradation, not real contention — watch this before reading the skip counter as "the feature is working as intended." |
| `yuzu_server_concurrency_reconcile_last_pass_unixtime` | gauge | Unix timestamp of the stale-claim reconciler's last tick (~5-minute cadence, folded into the existing result-set maintenance thread). A liveness signal — pair with `absent()`/staleness alerting to catch a reconciler that stopped ticking, the same shape `yuzu_server_audit_retention_last_pass_unixtime` uses. |
| `yuzu_server_concurrency_reconcile_declined_total` | counter | A reconciler pass declined by the clock-guard's anomaly classification (implausible clock jump, unusable prior state, or no persisted anchor yet — `audit_retention::classify`). A sustained nonzero rate means the reconciler is not force-releasing orphaned claims and needs investigation. |
| `yuzu_server_concurrency_claim_force_released_total` | counter | A concurrency claim force-released by the reconciler because its owning agent never reported a terminal status before `expires_at` — an orphaned claim from an agent crash, a disconnect mid-execution, or a cancelled-but-still-running execution (`mark_cancelled` deliberately does not release claims — see the ADR). |
| `yuzu_schedule_concurrency_mode_lookup_failed_total` | counter | A `ScheduleRunner` fire's second `get_definition()` read (needed to learn `concurrency_mode`) failed or returned empty — per-device enforcement was NOT applied to that one fire, which still dispatches (a deliberate fail-open, since the alternative for a `'once'` schedule is losing the fire permanently). Zero means the read has always succeeded. |

No dedicated alert rule ships for any of the six in this release — recommended follow-up, not
shipped: an `absent()` alert on the reconcile-liveness gauge (same shape as the audit-retention
sibling's alert), and a rate-based alert on `..._reconcile_declined_total` or
`..._claim_unavailable_total` if either is ever sustained nonzero.

**Useful PromQL queries:**

```promql
# Concurrency reconciler stopped ticking (liveness gauge hasn't advanced).
time() - yuzu_server_concurrency_reconcile_last_pass_unixtime > 900

# Any per-device dispatch exclusions in the last hour (informational, not itself alertable —
# exclusion is the mechanism working as intended, not a fault).
increase(yuzu_server_dispatch_concurrency_skipped_total[1h]) > 0
```

## Shutdown-time dispatch metrics (#3495)

| Metric | Type | Description |
|---|---|---|
| `yuzu_server_shutdown_dispatch_reach_zero_total` | counter | Fires on ANY dispatch through the shared `dispatch_confined` chokepoint (NOT quarantine-specific — MCP, REST, workflows, schedules, and every background engine funnel through the same seam) that reached zero agents while `ServerImpl::stop()` was in progress. **A correlated signal, not a precise one**, in two directions. False-positive direction: it cannot distinguish "`agent_server_->Shutdown(deadline)` forcibly cancelled the underlying stream write mid-dispatch" from "an ordinary zero-reach dispatch (every target offline, a quarantine denial) that happened to land during the shutdown window" — before #3495's fix moved that Shutdown call earlier in `stop()`, the former case existed as an invisible failure mode with no trace anywhere (governance sre finding, 2026-08-30). False-negative direction (governance unhappy-path, 2026-08-30): the condition is `outcome.sent == 0` — a dispatch that reached SOME targets before the write to the LAST one got forcibly cancelled has `sent > 0` and does not increment this counter at all, even though that partial-delivery case (some agents got the instruction, others silently didn't) is arguably the more concerning shape. No dedicated audit row backs it (the process may be exiting before one could be durably written); pair with the `spdlog::warn` line at the same call site, which names the `plugin`/`action`/`command_id`. Expect this to stay at `0` on a routine restart with no in-flight dispatches; a nonzero reading during a rolling deploy is worth a closer look, not an automatic page — no alert rule ships for it. |

## Quarantine store metrics (Guardian device-quarantine bookkeeping, ADR-0047)

The `QuarantineStore` — which agents are network-isolated, who isolated them, why, and their
full history (schema `quarantine_store`) — is a migrated PostgreSQL store (authoritative
posture). An active quarantine record is live security containment state, so a degraded read
must never be misread as "not quarantined".

| Metric | Type | Description |
|---|---|---|
| `yuzu_server_quarantine_read_degrade_total{reason}` | counter | A `list_quarantined`/`get_history` read degraded instead of returning a result. `reason` ∈ `read_concurrency_cap` (#881 — a **dispatch** waited for a containment-read slot and did not get one within its budget, so no store call was made. This value never means the store is unhealthy, and it does **not** degrade to the snapshot: a slot timeout **fails the dispatch CLOSED**, because serving stale state when nobody asked the store would under-enforce containment against a healthy one. The bound exists because a stalled backend would otherwise pin one pool connection per dispatching worker, and that pool is shared with every other store — measured, a frozen backend returns a successful query after 101s with neither `statement_timeout` nor `tcp_user_timeout` firing. A non-zero rate here means dispatch is being refused while Postgres may be answering correctly: check `yuzu_pg_acquire_wait_seconds` and `yuzu_pg_pool_in_use` for the stall), `store_not_open` (store failed to open at boot), `pool_acquire_timeout` (no Postgres connection available in time — correlates with `yuzu_pg_acquire_*` saturation), `query_error` (the query failed). All four series are pre-seeded at boot. **A non-zero rate on any of the three STORE reasons means `GET /api/v1/quarantine` is answering 503, not that no devices are quarantined** — an active containment could still exist behind the degraded read. `get_status` reports its own degrade via `std::expected` (the `db_error:`-prefixed `unexpected` case) but does **not** emit this counter — it has no REST/MCP caller today (confirmed by repo-wide grep), so this is a documented gap in the metric family's coverage, not a live blind spot; re-derive if a caller lands. **Does NOT cover the route-layer per-record authorization-check 503** (`"authorization check unavailable — try again"`, `rest_api_v1.cpp`'s admit-then-filter loop failing closed on an anomalous scope-check outcome) — that failure mode is entirely store-external (RBAC/engine-principal-store, not `QuarantineStore`) and is documented, not metered, in `docs/user-manual/upgrading.md` and `docs/user-manual/rest-api.md`; a 503 with that message and a flat counter here is expected, not a metric bug. |
| `yuzu_server_quarantine_gate_total{outcome}` | counter | One increment per **dispatch-time containment-gate evaluation** (#881) — the gate `dispatch_confined_arms` consults before it hands any `CommandRequest` to the registry. `outcome` is a closed four-value set, pre-seeded across all four at boot (`kQuarantineGateOutcomes`) so `absent()` cannot confuse "the gate has never had to fail closed" with "the gate never ran": `fresh` (the containment read succeeded — the normal path), `stale` (the read returned nothing and the gate served the last-known-good snapshot, which is trusted only while younger than **60s**), `fail_closed` (the store is durably unavailable, or the snapshot aged past that budget — the dispatch reaches **nobody**, on every arm including Broadcast, rather than guess who is contained), and `exempt_control_plugin` (the dispatch is the quarantine plugin's own control channel — `quarantine`/`unquarantine`/`status`/`whitelist` — which is never gated by the containment it administers, or release would be unreachable). **`fail_closed` is a fleet-wide dispatch outage, not a quarantine event**: it means instruction dispatch is refusing every target because containment state is unreadable. Alert on it. A sustained `stale` rate means the containment read is failing while the snapshot still covers it — the leading indicator of `fail_closed`. Per-denial evidence is the `quarantine.dispatch_denied` audit row plus `yuzu_server_dispatch_target_rejected_total{reason="quarantined"}`; this family counts gate EVALUATIONS, so a healthy fleet's `fresh` count rises with dispatch volume and means nothing on its own. |
| `yuzu_server_quarantine_reapply_total{result}` | counter | One increment per **reconnect re-application attempt or outcome** by `QuarantineContainmentReconciler` (#3425), triggered by a heartbeat from a device with an active-but-unconfirmed quarantine record or by the reconciler's own ~20s periodic tick. `result` is a closed eleven-value set, pre-seeded at boot (`kQuarantineReapplyResults`): `reapplied` (an apply or a follow-up `status` dispatch was accepted — `agents_reached > 0`), `confirmed` (a `status` read reported `state\|active` — the target agent's own self-report, the only outcome this repo treats as endpoint containment; not independently corroborated by any network-side signal, see `docs/user-manual/security-hardening.md`'s "Reconnect re-application" section), `unconfirmed` (a `status` read reported anything else — `partial`/`inactive`/`uncertain`/`degraded`, or an unparseable/`unknown` payload), `busy` (the agent-side mutation gate, #3429, answered `status\|busy` — treated as in-progress, not a failure; a pre-#3429 agent's `do_status` answers only `active`/`inactive`, so this value does not fire against that agent), `offline` (no live agent session — dispatch skipped entirely, no store write), `not_reached` (dispatched but `agents_reached == 0`, or no response arrived before the response-wait timeout), `rate_limited` (the per-agent claim was already held — this IS the no-spin mechanism, not an error), `pending` (an in-flight command is still within its response-wait window), `degraded` (a store or response read/write failed — see the correlation note below), `validation_failed` (the **stored** whitelist failed server-edge validation — `POST /api/v1/quarantine` validates at write time (#3425/`d1f71c58f`) and MCP's `quarantine_device` has always enforced this identical rule, so a fresh write can no longer land here; this now means a record written via the REST route before `d1f71c58f` shipped, or — on a fleet with pre-#3623 history — one migrated from a legacy `quarantine.db` by the since-retired `migrate_from_sqlite` backfill, which copied `whitelist` verbatim with no validation), `dispatch_error` (the dispatch call itself threw). **`degraded` is NOT reliably correlatable against `yuzu_server_quarantine_read_degrade_total`** (governance review, #3569): of this reconciler's eight `degraded`-counting call sites, only the `list_quarantined()` failure inside `tick()` increments that counter — the OTHER tick-level early return (`quarantine_store` never wired at construction), an uncaught exception anywhere in `tick()` (`on_tick_exception()`, governance round 12), and `QuarantineStore::get_status` (used by the session-churn re-verify path and `redispatch_stored_containment`) do **not** emit it (see that counter's own row above), the two durable-stamp write failures (`mark_endpoint_applied`/`mark_endpoint_confirmed`) are writes, not reads, and a `response_store` poll failure is an entirely different store with no counter of its own today. A `degraded` spike with `yuzu_server_quarantine_read_degrade_total` flat is expected, not a metric bug — it means the root cause is one of the other seven sites, not the listing read. Use `yuzu_server_quarantine_reconciler_tick_healthy` (below) to at least distinguish "the periodic tick itself is failing" (the three tick-level sites — never-wired, degraded read, or an uncaught exception) from "an individual per-agent apply/confirm/status call is failing" (the remaining five) — the gauge does not identify which of the five non-tick-level sites is degraded. |
| `yuzu_server_quarantine_reconciler_tick_healthy` | gauge | **1** if the reconciler's most recent `tick()` call reached its normal publish (a healthy `list_quarantined()` read, however many or few active records it found); **0** if that tick aborted early (the store was never wired, the read itself failed, or an uncaught exception propagated anywhere in `tick()` — governance round 12's `on_tick_exception()`, called from the tick-thread's outer catch in `server.cpp`) before reaching it. Not per-label — one series, but **per-replica** like `yuzu_server_quarantine_endpoint_unconfirmed` below: each server instance's reconciler thread ticks independently, so never `sum()` this series across instances — a healthy 3-replica fleet reads `3`, indistinguishable from "1 healthy + 2 that never emitted the series." Query per-`instance`, or `min by (instance) (...)` (see the query examples below) to catch any single replica going stale. Exists because `yuzu_server_quarantine_endpoint_unconfirmed` (below) is only ever `.set()` on the same successful-publish path — on a `tick_healthy=0` tick that gauge silently **freezes** at its last value rather than reflecting current (unknown) state, which is exactly backwards during the outage window an operator most needs a reliable signal (governance review, #3567). Pre-seeded to `1` at boot (the reconciler's tick thread starts within seconds, so a brief optimistic default before the first real tick is a negligible tradeoff). Only `tick()` writes this — `notify_agent_heartbeat`'s fast-path cache hit says nothing about whether the *last tick's own* read succeeded, so it does not touch this gauge. |
| `yuzu_server_quarantine_endpoint_unconfirmed{reachability}` | gauge | Active quarantine records whose endpoint containment `QuarantineContainmentReconciler` has not (yet, or no longer, after a session- or record-churn re-verify) confirmed via a `state\|active` `status` read. `reachability` ∈ `connected` (a live agent session exists — the reconciler could dispatch right now) / `offline` (no session). **Per-replica** — each server instance only sees the sessions its own gRPC listener holds, so **never `sum()` this series across instances**; query per-`instance` instead. Seeded at `0` for both label values at boot so a healthy fleet renders an explicit zero, not an absent series. `reachability="offline"` is EXPECTED to be non-zero and is deliberately not alerted on — a device quarantined while off is legitimately unconfirmed for its entire offline duration, and paging on that would be paging on correct behaviour (the same #2553/observability-conventions.md lesson already applied to `reason="quarantined"` dispatch denials). A sustained non-zero `reachability="connected"` count is the genuine divergence — see `YuzuQuarantineEndpointUnconfirmed`. |
| `yuzu_server_system_reserved_push_total{capability,result}` | counter | One increment per **server-internal push** that reaches an agent WITHOUT passing the containment gate above (#3402). These are not operator dispatch — they are the server keeping its own state coherent — and gating them would stop a contained device receiving the enforcement rules that make containment meaningful, so the bypass is deliberate. This counter makes it COUNTABLE — note that it is not *auditable* in this repo's sense: `send_system_reserved` never consults the gate, so it cannot label a push as having reached a contained device, and there is no per-event audit row. "On date D, did the server push `__guard__.push_rules` to contained device X" is not answerable from what ships. Tracked as a follow-up. `capability` is a closed four-value set matching the `SystemReservedPush` enum: `tar.fleet_snapshot`, `__guard__.push_rules`, `asset_tags.sync`, `__sync__.now`. `result` is `sent` (the registry accepted the frame — for a gateway-attached agent that is a QUEUE, not a delivery) or `undelivered`. **`undelivered` is the series that matters**: an undelivered `__guard__.push_rules` leaves a device unenforced, and before this counter existed that outcome fell on the floor at three of the four call sites. Both values of all four capabilities are pre-seeded at boot, because a zero you can alert on is worth more than an absent series you cannot. A new internal push cannot be added without adding an enumerator, so this family's label set cannot silently fall behind the code. **No alert rule ships for this family, deliberately.** `send_to` returns false whenever an agent's stream is null, which is what an ordinary suspended laptop looks like, and `tar.fleet_snapshot` fans out over the whole fleet on every visualization fetch — so a `> 0` rule is permanently firing on any real fleet, gets silenced, and takes the genuine "`__guard__.push_rules` never landed" signal with it. Query it during an investigation instead, and correlate an `undelivered` spike against agent connectivity before treating it as a server fault. |

`yuzu_server_quarantine_backfill_total{result}` (the one-time legacy `quarantine.db` →
PostgreSQL backfill outcome) was retired along with `QuarantineStore::migrate_from_sqlite()`
itself (chore/retire-migrate-from-sqlite-batch-a, #3623) — no production fleet ever ran a
pre-Postgres build, so there was no real `quarantine.db` data to migrate. See ADR-0047's Update.

**Useful PromQL queries:**

```promql
# Quarantine reads degrading → GET /api/v1/quarantine is answering 503; an
# active containment could be masked behind the degrade, never assume "clean".
sum(rate(yuzu_server_quarantine_read_degrade_total[5m])) by (reason) > 0

# Containment gate failing closed → instruction dispatch is reaching NOBODY
# because containment state is unreadable. This is an outage, not a quarantine.
sum(rate(yuzu_server_quarantine_gate_total{outcome="fail_closed"}[5m])) > 0

# The leading indicator: the read is failing but the 60s snapshot still covers it.
sum(rate(yuzu_server_quarantine_gate_total{outcome="stale"}[5m])) > 0

# An internal push that bypasses containment failed to reach the agent.
# For __guard__.push_rules that is a device left unenforced.
sum(rate(yuzu_server_system_reserved_push_total{result="undelivered"}[15m])) by (capability) > 0

# Reconnect re-application outcomes by result — a rising degraded share
# does NOT reliably correlate against yuzu_server_quarantine_read_degrade_total
# (see that counter's row above): only 1 of 7 degraded call sites does.
sum(rate(yuzu_server_quarantine_reapply_total[5m])) by (result) > 0

# Reachable devices whose endpoint containment is not yet confirmed — the
# genuine divergence signal (never sum() across replicas; max() picks the
# replica that actually holds the live session).
max by (instance) (yuzu_server_quarantine_endpoint_unconfirmed{reachability="connected"})

# Is the divergence gauge above even fresh right now? 0 means the reconciler's
# last tick aborted before publishing — the unconfirmed gauge is stale, not
# necessarily accurate, until this recovers to 1.
min by (instance) (yuzu_server_quarantine_reconciler_tick_healthy)
```

## RBAC store metrics (authorization substrate, ADR-0041)

The `RbacStore` — the PostgreSQL authorization substrate (schema `rbac_store`)
that backs `require_permission` / `require_scoped_permission` /
`authorize_list_read` — exports two counters, a histogram, and a gauge.
Authorization reads **fail closed (deny-on-degrade)**: when the store cannot
answer, it **denies** rather than allowing, so a degrade is a **fleet-wide
authorization-availability event**, not a silent partial outage.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `yuzu_server_rbac_read_degrade_total` | counter | `reason` | An authorization-cache read against `rbac_store` was affected by a degrade. **Three reasons DENY**: `pool_acquire_timeout` (no PG connection available in time — also recorded here when the fail-fast circuit breaker denies without touching the pool, since a breaker-open denial is one of this reason's two contributing failure modes, not a distinct reason), `query_error` (the authz query failed), `generation_refresh_failed` (the durable cross-replica cache-coherence token could not be re-read PAST the bounded ~5s stale-serve window — treated as "assume changed", cache cleared) — a non-zero rate on these means callers are being denied because the substrate is unhealthy. **Three reasons are OBSERVE-ONLY and deny nothing** (fjarvis #2703 F2/F3 + the 2026-08-11 bounded-stale-serve split): `rbac_enabled_non_canonical` (a periodic refresh read a durable `rbac_enabled` value that wasn't exactly `"true"`/`"false"`; the cached enabled-state is left unchanged rather than coerced), `stale_beyond_accepted_bound` (a reader landed inside an in-flight generation refresh that was already past the accepted ~1s staleness bound; the read still proceeds from the pre-refresh cache), and `generation_refresh_failed_within_bound` (a generation refresh failed but the store is still inside the bounded ~5s stale-serve window from ADR-0041's "Update" — the existing cache keeps answering unchanged; early warning only, nobody is denied). The `YuzuRbacReadDegraded` alert is scoped to the three denying reasons only. |
| `yuzu_server_rbac_authz_check_seconds` | histogram | none | End-to-end latency of `check_permission` — acquire + query + cache lookup, every outcome including cache hits and breaker-denied fast paths. Extended buckets out to 60s (not the default 10s ceiling), because the measured lock-contention tail on this path runs to ~18.5s and, per the dark-network analysis in the SOC2 doc's availability-posture note, as far as ~40s. Distinct from `yuzu_pg_acquire_wait_seconds`, which reads fast even when the acquire itself succeeds but the query afterward blocks on `PgPool`'s injected `lock_timeout` — this histogram is the only place that scenario's true end-to-end cost is visible. |
| `yuzu_server_rbac_breaker_open` | gauge | none | `1` when the authz-hot-path fail-fast circuit breaker is open (2 consecutive `pool_acquire_timeout`/`query_error` failures), `0` when closed. Per-process/per-replica, not fleet-wide — a fleet-wide view needs `count(yuzu_server_rbac_breaker_open == 1)` across replicas. |

`yuzu_server_rbac_backfill_total` (the one-time legacy `rbac.db` → PostgreSQL backfill outcome)
was retired along with `RbacStore::migrate_from_sqlite()` itself
(chore/retire-migrate-from-sqlite-batch-a, #3623) — no production fleet ever ran a pre-Postgres
build, so there was no real `rbac.db` data to migrate. See ADR-0041's Update.

**Example output:**

```
# HELP yuzu_server_rbac_read_degrade_total RBAC authorization-cache reads affected by a degrade (see label docs — not all reasons deny)
# TYPE yuzu_server_rbac_read_degrade_total counter
yuzu_server_rbac_read_degrade_total{reason="pool_acquire_timeout"} 0
yuzu_server_rbac_read_degrade_total{reason="query_error"} 0
yuzu_server_rbac_read_degrade_total{reason="generation_refresh_failed"} 0
yuzu_server_rbac_read_degrade_total{reason="generation_refresh_failed_within_bound"} 0
yuzu_server_rbac_read_degrade_total{reason="rbac_enabled_non_canonical"} 0
yuzu_server_rbac_read_degrade_total{reason="stale_beyond_accepted_bound"} 0

# HELP yuzu_server_rbac_authz_check_seconds End-to-end latency of RbacStore::check_permission
# TYPE yuzu_server_rbac_authz_check_seconds histogram
yuzu_server_rbac_authz_check_seconds_bucket{le="0.005"} 0
yuzu_server_rbac_authz_check_seconds_bucket{le="0.01"} 0
yuzu_server_rbac_authz_check_seconds_bucket{le="0.025"} 0
yuzu_server_rbac_authz_check_seconds_bucket{le="0.05"} 0
yuzu_server_rbac_authz_check_seconds_bucket{le="0.1"} 0
yuzu_server_rbac_authz_check_seconds_bucket{le="0.25"} 0
yuzu_server_rbac_authz_check_seconds_bucket{le="0.5"} 0
yuzu_server_rbac_authz_check_seconds_bucket{le="1"} 0
yuzu_server_rbac_authz_check_seconds_bucket{le="2.5"} 0
yuzu_server_rbac_authz_check_seconds_bucket{le="5"} 0
yuzu_server_rbac_authz_check_seconds_bucket{le="10"} 0
yuzu_server_rbac_authz_check_seconds_bucket{le="15"} 0
yuzu_server_rbac_authz_check_seconds_bucket{le="20"} 0
yuzu_server_rbac_authz_check_seconds_bucket{le="30"} 0
yuzu_server_rbac_authz_check_seconds_bucket{le="45"} 0
yuzu_server_rbac_authz_check_seconds_bucket{le="60"} 0
yuzu_server_rbac_authz_check_seconds_bucket{le="+Inf"} 0
yuzu_server_rbac_authz_check_seconds_sum 0
yuzu_server_rbac_authz_check_seconds_count 0

# HELP yuzu_server_rbac_breaker_open 1 when the authz fail-fast breaker is open, 0 when closed
# TYPE yuzu_server_rbac_breaker_open gauge
yuzu_server_rbac_breaker_open 0
```

**Suggested alert (a degrade on one of the three denying reasons denies authz fleet-wide):**

```promql
# Scoped to the three DENYING reasons only — rbac_enabled_non_canonical,
# stale_beyond_accepted_bound, and generation_refresh_failed_within_bound
# share this metric but deny nothing, so folding them into this expression
# would page a false "callers denied fleet-wide".
sum(rate(yuzu_server_rbac_read_degrade_total{reason=~"pool_acquire_timeout|query_error|generation_refresh_failed"}[5m])) by (reason) > 0
```

The shipped rule is `YuzuRbacReadDegraded` in `docs/prometheus/yuzu-alerts.yml`.

## Useful PromQL queries

### Fleet overview

```promql
# Total connected agents
yuzu_agents_connected

# Connected agents by OS
sum by (os) (yuzu_fleet_agents_by_os)

# Connected agents by architecture
sum by (arch) (yuzu_fleet_agents_by_arch)
```

### Request performance

```promql
# Request rate (per second, 5-minute window)
rate(yuzu_http_requests_total[5m])

# 95th percentile command-execution latency
# (the server emits no general HTTP request-duration histogram; command duration
#  is its primary latency SLI — see also auth-login and viz-topology histograms)
histogram_quantile(0.95, sum(rate(yuzu_command_duration_seconds_bucket[5m])) by (le))

# Error rate (percentage of 5xx responses)
sum(rate(yuzu_http_requests_total{status=~"5.."}[5m]))
/ sum(rate(yuzu_http_requests_total[5m])) * 100
```

### Agent health

```promql
# Healthy agents reported via heartbeat status_tags.
# (Agents have no Prometheus endpoint, so there is no per-agent heartbeat-latency
#  series; the server re-exports fleet health as this gauge.)
yuzu_fleet_agents_healthy

# Plugin execution failure rate by plugin
sum by (plugin) (rate(yuzu_agent_commands_executed_total{status="failure"}[5m]))
/ sum by (plugin) (rate(yuzu_agent_commands_executed_total[5m])) * 100
```

### Guardian durable-journal health (heartbeat `status_tags`)

> **Not yet active in a shipped release.** The Guardian durable journal and the worker that
> maintains it are wired but DORMANT: they run only once the Spark detection path becomes the
> authoritative backend, and that flag is off in every released agent. Until then none of the
> counters below can be anything but absent, and the failure modes described - a wedged journal,
> a dead maintenance worker, a clock anomaly - are not reachable. This section is written for
> the release that turns it on; treat it as reference, not as something to alert on today.

The agent has no Prometheus endpoint, so the Guardian lifecycle journal reports through
heartbeat `status_tags`. Emission is SPARSE - a quiescent or inert journal ships no tags at
all, so absence means "nothing to report", not "not collected". One exception: the two
`_stale_seconds` age tags below are emitted every heartbeat **including `0`** while the drain
worker is live (a zero age is a real "fresh" reading), and are absent only while the journal
path is dormant.

| Tag | Meaning | What to do |
|---|---|---|
| `yuzu.guardian_journal_maint_exceptions` | Cumulative JOURNAL passes that threw and were firewalled: the heartbeat's retry-persist plus the drain worker's retention prune and replay paging. Convergence sweeps are NOT included - they have their own tag below. Nonzero means the journal path hit an exception (typically `bad_alloc` under memory pressure) and was contained rather than terminating the agent. It covers the firewalled journal paths - persist on the heartbeat, at boot re-arm, on rule-apply and at shutdown; the reconnect kick; and the worker's retention and replay passes - plus one increment for the drain worker's own loop terminating, which stops outbox DELIVERY too. That last case is named in a `critical` log line and, unlike the others, increments once and never again. | Investigate endpoint memory pressure. A steadily climbing value with a growing `yuzu.guardian_journal_bytes` means retention is not keeping up. A value that increments exactly once and then stays flat while the journal grows is the loop-termination case; check the agent log for the `critical` line and restart the daemon. |
| `yuzu.guardian_journal_write_capacity_rejected` | Records refused because the journal is at its hard write ceiling. | Check whether prune is failing (`yuzu.guardian_journal_prune_failures`) or the store is unwritable. |
| `yuzu.guardian_journal_gauge_underflow` | The write-ceiling check read the live size gauge as **negative** - a size-accounting bug. Persist then fails **closed** (RAM staging only) until a prune rebase restores the gauge. `yuzu.guardian_journal_batch_count` clamps the negative to 0, so the journal looks empty while it is actually refusing writes; this tag is the only signal of that state. | Any nonzero is a real bug - capture the agent log and file it. A sustained climb alongside `yuzu.guardian_journal_stage_dropped` means the underflow is now costing records. |
| `yuzu.guardian_journal_prune_failures` | Retention passes that could not read the journal. | A sustained nonzero value means the shared `kv_store.db` is busy or corrupt. |
| `yuzu.guardian_journal_page_read_failures` | Replay READS that could not read the journal - the candidate scan (at most once per pass) plus, since #2299, each per-candidate value read a pass attempts (bounded by the 128-candidate cap). The unit is failed READS, not failed passes: one pass can add several, so do not read a rate off this as a pass-failure rate. | Separate from `prune_failures` on purpose: retention can be succeeding while replay is stalled, in which case records are being deleted on schedule and shipped never. A sustained nonzero value with a healthy `prune_failures` is the worse of the two. |
| `yuzu.guardian_journal_clock_jump_skips` | Retention passes that declined to age-evict because the pass would have aged out the ENTIRE journal at once. | NOT an error: the journal deliberately kept evidence it would otherwise have deleted. It fires once per DISTINCT decline (the guard dedups on the whole set of facts behind the decline, not a single latch bit) - most clock jumps trip it once, but a live jump landing on an already-expired backlog can trip it TWICE in a row (a Step decline, then a Wipe decline on the very next pass, before eviction resumes) - do not assume one increment means one incident. The usual cause is a clock that moved - a VM restored from an old snapshot, or a bad NTP correction - but a legitimately long-offline endpoint whose whole (small) journal expired together looks identical. Check the endpoint's clock first UNLESS `yuzu.guardian_journal_prune_failures` is climbing on the same endpoint at the same time - that combination points to a storage/delete fault (the guard's decline/retry cycle re-trips on every attempt), not a clock fault. If it jumped forward, replay keeps ATTEMPTING delivery of the survivors either way - the paced ageing-out deliberately stops treating them as unshippable - but the per-pass cap keeps deleting the oldest ones out from under it, and deletion currently outruns replay by roughly five to one. Correcting the clock is what stops that race rather than what starts delivery, and it takes effect on the next retention pass. Expect a burst of redelivered events during a paced ageing-out; the server de-duplicates them. Note the cap applies to AGE only - if the journal is also over its COUNT ceiling, that ceiling is uncapped and trims the oldest batches in a single pass regardless. |
| `yuzu.guardian_journal_evicted_no_send_evidence` | Batches aged out with no record of ever being sent - a possible audit gap. | Correlate with connectivity outages for that endpoint. A spike alongside `yuzu.guardian_journal_clock_jump_skips` means the endpoint's clock moved rather than that the link was down - check the clock before concluding evidence was genuinely lost. Since #2299 also cross-check `yuzu.guardian_journal_quarantined`: quarantine of a corrupt-VALUE batch moved to the replay pass, so a corrupt batch the replay rotation never reaches before it ages out is counted HERE rather than as quarantined. Both are genuinely lost evidence, but on a mass-corruption endpoint this counter no longer separates "never delivered" from "never deliverable". |
| `yuzu.guardian_journal_evicted_unclassified` | Batches aged out whose sent/unsent disposition was never determined - the third eviction outcome, mutually exclusive with the two above. It makes the eviction accounting exact (`pruned` == the three summed), so `_evicted_no_send_evidence` reads as a floor rather than an undercount. **Neither** an audit gap **nor** a delivered batch. | Read by cause. A single one-off increment coinciding with an agent shutdown is the stop-before-classification case (benign, at most once per process lifetime; since #2470 a stop during scan-OK classification no longer lands here - only a stop mid-fallback-loop does). A value that climbs with `yuzu.guardian_journal_prune_failures` is the unreadable-sent-label case - investigate the shared `kv_store.db` as for that counter. A jump alongside `yuzu.guardian_journal_maint_exceptions` is a mid-classification `bad_alloc` (memory pressure) - the remainder is accounted here and the throw counted there. In-memory only; resets on restart, and the shutdown-skip increment may not survive to a final heartbeat. |
| `yuzu.guardian_drain_exceptions` | Firewalled throws in the outbox DELIVERY machinery on the drain worker. | Events are buffered but not shipping. Distinct from the journal counter - delivery failing and retention failing need different responses. |
| `yuzu.guardian_send_exceptions` | Per-entry drain **sends** that threw - finer-grained than `_drain_exceptions`: a single entry could not be serialized/sent, so its log's head is retained and that drain **stops**, jamming delivery behind a permanently-failing entry. Spans the lifecycle log and the general outbox. | A sustained nonzero value with otherwise-healthy streaming means an entry is stuck at the head; capture the agent log for that entry. |
| `yuzu.guardian_journal_backpressure_drops` | Lifecycle-audit entries **rejected** at outbox enqueue because it was at capacity. A **loss** channel: the arm/disarm still succeeds (the audit trail never blocks a real detection-capability change) but the record of that change is dropped. | A nonzero value means the audit trail is missing lifecycle edges under sustained delivery backpressure - investigate why delivery is not draining. |
| `yuzu.guardian_send_orphan_exceptions` | An outbox-send reclaim (either lane) whose orphaned worker's result was a thrown exception, **discarded** rather than attributed - the orphaned result belongs to a superseded entry (a generation-supersede purge or a withdrawal moved the log's head while the old head's send was still running) with nowhere correct to attribute it. Diagnostic signal, not a loss channel: the discard itself is correct. | A climbing value means sends are throwing often enough to be reclaimed as orphans before their result can be attributed; capture the agent log for the underlying send failure. |
| `yuzu.guardian_send_stalls` | An outbox send (either lane, same-entry or a mismatched orphan) that exceeded its stall threshold before completing or being reclaimed. | A nonzero value means at least one endpoint's outbox delivery is running slow, not necessarily failing - a paired recovery log line ("completed after having stalled") confirms the send eventually resolved. |
| `yuzu.guardian_sweep_exceptions` | Firewalled throws in the convergence SWEEP lanes. | Drift DETECTION is degraded (the endpoint may miss policy violations); the audit trail itself is unaffected. |
| `yuzu.guardian_journal_bytes` / `yuzu.guardian_journal_batch_count` | Current on-disk size and batch count of the journal. Gauges, not counters. | Not independently actionable - use them to interpret the rows above (a climbing size alongside `prune_failures` means retention is not keeping up). |
| `yuzu.guardian_journal_page_stale_seconds` / `yuzu.guardian_journal_prune_stale_seconds` | Seconds since the drain worker's last page pass that made **replay progress or verified there was none** / last prune pass that **actually ran retention** (applied the delete or verified nothing eligible), seeded from worker start. **Replay/retention-progress** gauges (flip item 6, #2452): a dead, hung, or permanently-throwing worker reads as an ever-growing age - AND so does one whose page passes are token-starved, read-failing, boot-barrier-stalled, **window-blocked (headroom)**, or **quarantine-only (mass corruption)**, or whose prune **scan, DELETE, or completion** is failing (scan-fail / delete-fail / stop-aborted), **declining age eviction of expired rows on a clock anomaly**, or **unable to quarantine a stuck malformed key**. Each gate is a single positive signal (`progress_or_verified_idle` for page, `progress_or_verified` for prune), so any no-work exit reads stale by construction. A pass that placed records / evicted rows, or positively established there was nothing to do, still reads fresh (a forward-clock-jump WIPE is the one prune case that reads fresh despite an anomaly - the delete did succeed, so the clock guard, not this gauge, owns it). Emitted every heartbeat **including `0`** while the worker is live; absent while dormant. Two tags because the cadences differ (30 s page / 120 s prune) and stall independently. | Healthy readings hover around each pass's cadence. A steadily growing age with climbing `maint_exceptions` means every pass is throwing now; with a **flat** `maint_exceptions` the worker is hung, its loop died earlier (loop death increments that counter exactly once and logs a `critical` line - check the agent log), **or** its passes are stalling short of progress - read alongside `page_read_failures` / `prune_failures` and `deferred`-class signals to tell which. Either way the journal is unmaintained - see the restart caveat below. |
| `yuzu.guardian_journal_headroom_blocked_seconds` | Age of the current headroom-blocked **replay-congestion episode** (#2364): a journal batch could not be placed in the send window for lack of room, continuously since the value's start. Sampled at pass granularity; clears only after a proven block-free sweep of all candidates (the batches a replay pass currently considers); resets on agent restart; a forced (boot/reconnect) pass can start an episode from already-delivered batches. **Sparse**: absent = no current episode. | Sustained growth means the send window is not draining while a backlog waits - check connectivity and the delivery counters. The loss-relevant threshold is the 7-day retention window (604 800 s): an episode approaching it means never-sent records are nearing deletion (`_evicted_no_send_evidence`). A clear can coincide with the blocked batch's own eviction - corroborate against `_evicted_no_send_evidence` before reading a clear as recovery. |

**A gap the age gauges close (formerly "Known gap"):** the counter tags alone cannot
distinguish a healthy idle worker from a dead one - they are sparse, so a worker that stops
before doing any work reads exactly like one with nothing to do, and a worker that HANGS (blocked
indefinitely on a store call) throws nothing for the firewall to catch. The `_stale_seconds`
gauges above are the fix (flip items 6/14): they are seeded at worker **start** and re-stamped
only by a pass that made real progress or positively verified there was nothing to do (#2452) -
for page, records placed OR a completed scan of a clean, unblocked, uncorrupted, readable backlog;
for prune, retention applied (the delete succeeded) OR a clean scan verifying nothing was eligible.
So not just dead, hung, and permanently-throwing workers but also token-starved, read-failing,
window-blocked (headroom), and mass-corruption (quarantine-only) page workers, and scan-failing /
delete-failing / stop-aborted / clock-declining / quarantine-stuck prune workers, all read as an
ever-growing age - and because they
are emitted including `0`, "fresh" is a real reading, not an absence. What they still cannot show is a worker that **never started at all**: no worker
means the tags are absent, which post-cutover is itself the anomaly to look for on a rule-bearing
agent. There is no restart primitive short of restarting the agent daemon, and a restart is not
free: records already written to the journal survive it, but `GuardianEngine`'s shutdown holds
its lock while it joins the drain worker, so a stop arriving while that worker is hung rather
than dead can itself be cut short by a supervisor's stop timeout. Prefer a graceful stop, and
confirm the process exited on its own rather than being killed.

Note the tag KEY is not always the internal field name - the audit-gap row above is emitted
as `..._evicted_no_send_evidence` though the field is `evicted_without_send_evidence`. Grep
heartbeat payloads for the key in this table, not for the field name; the emitter in
`agents/core/src/guardian_journal_heartbeat.hpp` is authoritative.

This table covers the actionable subset. The emitters ship about thirty
`yuzu.guardian_journal_*` tags in total (the counters sparsely - only non-zero ones - plus the
age tags per their own posture above), so a tag absent from this table is not necessarily
absent from the payload.

Counters are cumulative for the agent process and reset on restart.

### Guardian arm-ledger + io-ceiling health (heartbeat `status_tags`, rung 9c PR-3)

> **Not yet active in a shipped release** - same caveat as the journal section above:
> dormant until the Spark detection path becomes authoritative (`prefer_spark` off in
> every released agent today).

Two more Guardian heartbeat signals, both new in rung 9c PR-3, neither part of the
journal family above:

| Tag | Meaning | What to do |
|---|---|---|
| `yuzu.guardian_arm_pending` / `yuzu.guardian_arm_failed` | The ack ledger's CURRENT application snapshot - accepted-and-still-outstanding arms, and arms resolved to a non-Committed terminal outcome, respectively. **Re-statable gauges, emitted together, including a genuine `0`** - unlike the sparse journal counters above, absence here means dormant: `prefer_spark` off, the engine stopped, Spark itself unavailable (Unwired/SparkFailed/SparkDisabled), or no current application exists yet - not "nothing to report while live". A rule genuinely at zero pending/failed reads as `0`, not absent - an omitted tag would misreport as "dormant" rather than "checked, healthy". | Sustained nonzero `_pending` beyond a couple of heartbeat ticks (~30 s each) means arms are taking longer than expected to resolve - check backend/OS-call latency. A nonzero `_failed` means at least one rule failed to arm and its generation is held; find the failing rule (agent log) before assuming the fleet compliance view is complete. `_failed` resets to `0` the moment a NEW application begins - the server's ~25 s `full_sync` retry of a generation that previously failed - regardless of whether that retry itself then succeeds; if the retried rule fails again, `_failed` climbs back up over the following ticks rather than staying at `0`. **Alerting hazard**: because that reset fires on every retry attempt (not just a successful one), a naive `yuzu_fleet_guardian_arm_failed > 0 for: 5m` rule has its `for:` timer restarted by the ~25 s retry cadence and can mask a persistently-wedged rule indefinitely - alert on `arm_pending + arm_failed > 0` sustained instead. **Do NOT rely on `yuzu.guardian_generation` lag as an alternative once rung 9c PR-5e's K-bound waiver is live (#4221)**: after 3 identical re-applies of a persistently Wedged-only key (every OTHER outstanding failure in the application, if any, still holds the acknowledgment indefinitely regardless), the generation acknowledges (catches up, no lag) while `arm_failed` stays sustained nonzero for that same rule - a generation-lag-only detector reads a K-waived, still-failing rule as healthy. **The "3" is a shared, per-application-sequence counter, not per-rule** - a rule can be waived on its very first observed wedge if an unrelated sibling's own ordinary, now-cleared failure already funded the count (`docs/spark-legacy-delta-registry.md` Row A3). `arm_failed` sustained nonzero is the durable signal for the CURRENT application only (per this row's own "resets to `0` the moment a NEW application begins" sentence above - a later, distinct push still zeroes it unconditionally; this is not a durable cross-application "still failing" gauge); treat generation catch-up as orthogonal, not confirming. Same-application recovery landed for the **Wedged case only** (rung 9c PR-5d): a Wedged receipt whose late arm succeeds and is adopted clears here without waiting for a new application; every other non-Committed status still only clears via a new application. |
| `yuzu.guardian_io_arm_disarm_rejected_ceiling` | Admissions refused at the arm/disarm executor's per-instance physical alive-worker ceiling (R5.1). **Sparse**: `0` omits the tag. Scoped to the arm/disarm executor instance only - the state reader's own executor instance cannot reach this ceiling (it uses only the bounded, quota-released-at-return form). | A nonzero, climbing value means completion callbacks on that instance are piling up (slow or wedged OS calls) faster than they retire - investigate backend latency on that endpoint. This tag names the fault class only; it does not say whether the endpoint is CURRENTLY wedged (no windowed detector ships yet). |

### How long Guardian audit evidence is retained ON the endpoint

The durable lifecycle journal keeps records locally until they are replayed to the server,
bounded by whichever of these is reached first:

| Cap | Value | Behaviour at the cap |
|---|---|---|
| Age | 7 days | Older batches are evicted on the next retention pass |
| Batch count | 1000 (soft) / 2000 (hard ceiling) | Oldest-first eviction at the soft cap; writes are REFUSED at the hard ceiling |
| Size | 32 MiB (soft) / 64 MiB (hard ceiling) | As above |

Eviction is keyed off each batch's recorded wall-clock timestamp, so the window survives a
reboot. This is the ENDPOINT-side window only - once records reach the server they follow the
server's own retention (see `guaranteed-state.md`). An endpoint offline for longer than the
age cap, or generating more than the count/size caps allow, will have the excess evicted
locally; `yuzu.guardian_journal_evicted_no_send_evidence` counts the batches that aged out
with no evidence of ever having been sent.

### Plugin load + signing rejections (`yuzu_agent_plugin_rejected_total`)

Counter incremented every time the agent rejects a plugin at scan time
**before** the plugin's code runs. The `reason` label is bounded to a
fixed set of stable string prefixes — alert rules SHOULD pin against
the literal label values, not substring matches.

| Reason label | Meaning | Operator action |
|---|---|---|
| `reserved_name` | Plugin declared a reserved name (`__guard__`, `__system__`, `__update__`, `__guardian_journal__`, `__guardian__`, `__sync__`). Possible plugin-author error or a malicious shadowing attempt (#453; the `kv_store`-namespace names added in #2303). | Investigate the plugin source / drop. |
| `load_failed` | `dlopen` / `LoadLibrary` failed, missing `yuzu_plugin_descriptor` export, or ABI version mismatch. | Check the agent log for the dlopen error and rebuild the plugin against the current SDK ABI. |
| `signature_missing` | `--plugin-trust-bundle` is set, `--plugin-require-signature` is set, and a plugin has no `<plugin>.so.sig` sibling. | Sign the plugin, deploy the `.sig` alongside, or relax the require flag. |
| `signature_invalid` | `.sig` file exists but the CMS verification failed at the signature/digest layer (most commonly: the plugin file was modified after signing). | Re-sign the plugin or investigate tampering. |
| `signature_untrusted_chain` | The signing cert does not chain to a CA in the operator's trust bundle, OR the leaf cert lacks `EKU=codeSigning`, OR the cert chain has expired. | Verify the bundle includes the right CA root; re-issue a leaf with `extendedKeyUsage=codeSigning`; rotate expired CAs. |

```promql
# WARN: any plugin rejected for an invalid signature in the last 5 min
# (most often: tampered file in the plugin dir).
increase(yuzu_agent_plugin_rejected_total{reason="signature_invalid"}[5m]) > 0

# CRITICAL: chain validation failure means a plugin was signed against
# a CA the operator's trust bundle doesn't anchor — supply-chain signal,
# or an expired/revoked operator CA.
increase(yuzu_agent_plugin_rejected_total{reason="signature_untrusted_chain"}[5m]) > 0

# Volume tracker: missing-sig rejections during a signing rollout
# (transitional → enforced). Expect this to be non-zero only during
# rollout, then drop to 0 once every plugin has a .sig sibling.
sum by (instance) (increase(yuzu_agent_plugin_rejected_total{reason="signature_missing"}[1h]))

# Reserved-name attempts (#453) — should be 0 in normal operation.
increase(yuzu_agent_plugin_rejected_total{reason="reserved_name"}[5m]) > 0
```

### Instruction throughput

```promql
# Instructions completed per minute
rate(yuzu_commands_completed_total[5m]) * 60

# Average instruction duration
rate(yuzu_command_duration_seconds_sum[5m])
/ rate(yuzu_command_duration_seconds_count[5m])
```

## Grafana integration

Yuzu ships pre-built Grafana dashboards. The operational set lives in
`deploy/grafana/` (`yuzu-dashboard`, `yuzu-fleet-dashboard`, and
`yuzu-gateway-dashboard` over Prometheus, plus `yuzu-analytics-dashboard` over
ClickHouse) and is auto-provisioned by the UAT / full-UAT rigs; a standalone
Prometheus import template is at `docs/grafana/yuzu-overview.json`. See
[`docs/grafana/README.md`](../grafana/README.md) for the full list and import
instructions.

To build your own, import the Prometheus data source into Grafana and use the
PromQL queries above. A typical Yuzu dashboard includes:

| Panel | Visualization | Query |
|---|---|---|
| Connected agents | Stat / single value | `yuzu_agents_connected` |
| Agents by OS | Pie chart | `sum by (os) (yuzu_fleet_agents_by_os)` |
| Request rate | Time series | `rate(yuzu_http_requests_total[5m])` |
| Command latency (p95) | Time series | `histogram_quantile(0.95, sum(rate(yuzu_command_duration_seconds_bucket[5m])) by (le))` |
| Error rate | Time series | `5xx / total * 100` |
| Instruction throughput | Time series | `rate(yuzu_commands_completed_total[5m])` |

### Alerting rules

Example Prometheus alerting rules for Yuzu:

```yaml
groups:
  - name: yuzu
    rules:
      - alert: YuzuNoAgentsConnected
        expr: yuzu_agents_connected == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "No agents connected to Yuzu server"

      - alert: YuzuHighErrorRate
        expr: >
          sum(rate(yuzu_http_requests_total{status=~"5.."}[5m]))
          / sum(rate(yuzu_http_requests_total[5m])) > 0.05
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Yuzu server error rate above 5%"

      - alert: YuzuHighCommandLatency
        expr: |
          histogram_quantile(0.99, sum(rate(yuzu_command_duration_seconds_bucket[5m])) by (le)) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Command p99 latency exceeds 10 seconds"
```

## Security considerations

### Fleet metadata in metrics labels

The `/metrics` endpoint exposes aggregated fleet composition data through gauge metrics:

| Metric | Labels | Information exposed |
|---|---|---|
| `yuzu_fleet_agents_by_os` | `os` | OS distribution (windows, linux, darwin counts) |
| `yuzu_fleet_agents_by_arch` | `arch` | CPU architecture distribution (x64, arm64 counts) |
| `yuzu_fleet_agents_by_version` | `version` | Agent version inventory |
| `yuzu_fleet_perf_cohort_*` | `cohort` | **Operator tag values** (only when the opt-in cohort export key is set — Settings → DEX alerts). Cohort labels carry the raw tag values of the exported key; if those values encode personnel-relevant or confidential groupings (`department`, `cost-center`, owner names…), they flow to whatever scrapes `/metrics`, including third-party monitoring stacks. **Choose export keys whose values are non-sensitive organizational identifiers** (hardware model, image name). |

This data reveals your fleet's attack surface to anyone who can reach the metrics endpoint. An attacker who learns that 80% of your fleet runs Windows x64 with agent v0.4.2 can target known vulnerabilities for that specific combination.

**Mitigations (in order of preference):**

1. **Keep the default** — remote `/metrics` access requires authentication. Localhost is always open for co-located Prometheus.
2. **Restrict network access** — if Prometheus scrapes remotely, use firewall rules or a reverse proxy with authentication in front of the metrics endpoint.
3. **Use `--metrics-no-auth` with caution** — only enable unauthenticated remote access when the metrics endpoint is on a trusted monitoring network, not exposed to the general corporate network or internet.
4. **API token auth** — when available (Phase 3), create a dedicated metrics-scraper API token with read-only scope.

> **Default posture:** The server binds to `127.0.0.1` and requires auth for remote `/metrics` access. No action is needed if you scrape from localhost.

## Planned features

| Feature | Roadmap | Description |
|---|---|---|
| System health dashboard | Phase 7, Issue 7.2 | Server CPU, memory, connection counts, queue depths |
| Topology map | Phase 7 | Visual map of server nodes, gateways, and agent counts |
