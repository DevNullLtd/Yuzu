- **Breaking — `/readyz` now goes red when the server cannot reach a writable Postgres primary, and
  shutdown can hold a drain grace for load balancers (HA WS-8, ADR-2002 §12).** A new gating `pg_reachable` row is
  fed by a probe on its own dedicated Postgres connection (not the pool), with client-side deadlines on
  every socket wait and one deadline per host of a multi-host DSN. `/readyz` reports not ready after two
  failed probes, at once when the probe reaches a standby or a primary with
  `default_transaction_read_only` on, or after 15 s without a success. The 503 body names the reason in a new `pg` field
  (`unreachable`, `stale`, `read_only`, `not_yet_probed`). Before this, `/readyz` stayed 200 through a
  database outage whenever the pool held idle connections. Store rows are now documented as startup
  checks (#3061). New `--shutdown-drain-seconds` / `YUZU_SHUTDOWN_DRAIN_SECONDS` (0–60, default 0) keeps
  the server serving for that long after `/readyz` turns `503 draining` on `SIGTERM` (raise the
  orchestrator's stop timeout by the same amount). New metrics
  `yuzu_server_pg_reachable`, `yuzu_server_pg_reachability_last_success_age_seconds` and
  `yuzu_server_pg_reachability_probe_failures_total`, plus alert `YuzuServerPostgresUnreachable`. Each
  server uses one more Postgres connection. A multi-host `--postgres-dsn` now requires
  `target_session_attrs=read-write`: it is added when absent (the DSN is rebuilt from libpq's parse and
  re-checked), and any other explicit value except `primary` refuses boot, as does
  `load_balance_hosts` (other than `disable`) — checked on the DSN, the environment and, on the first
  connection, any service file (the readiness probe repeats the check whenever it reconnects —
  restart the server after editing a service file). Point liveness probes at `/livez`, not `/readyz` — see
  `docs/user-manual/upgrading.md`.
