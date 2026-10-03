- **The server's `Guardian T_server` diagnostic line is now written asynchronously (#4666).**
  It previously ran on the thread that reads an agent's Subscribe stream (or the gateway
  forwarding path), so a stalled log sink (an undrained pipe, a stalled network-mounted log
  path) could block that thread. It now enqueues onto its own small, bounded, dedicated logger
  (`overrun_oldest` eviction under sustained overload, matching the agent-side async logger
  #4666 already shipped) and returns immediately. Not a breaking change: same format, same
  neutralised identifiers, and `--log-level`/the `log_level` runtime-configuration key still
  fully control it. The server's other Guardian ingest log lines on the same code path
  (idempotent-redelivery, event-collision/store-error, oversized-`detail_json`/parse-failure, and
  the observation-only blast-radius/alert-router warning pair) are unaffected and stay
  synchronous. One observable side effect: because `T_server` now drains through its own queue,
  it can appear later in the log stream than an adjacent line from a later event on the same code
  path, even though the underlying events were ingested in order — do not rely on log-file line
  order across these lines. Temporary diagnostic infrastructure, not a permanent product
  surface — retired once #4606 closes. See the `Guardian T_*` diagnostic log lines section
  (vNEXT) in `docs/user-manual/server-admin.md`.
