- **The packaged gateway config caps its listeners' connections, and a Register
  refused while the upstream client restarts is answered `UNAVAILABLE`.** The
  release config the gateway packages and the systemd unit run
  (`gateway/config/sys.config`) now sets the same listener `limits` as
  `sys.config.prod`: at most 60000 agent connections (sized to the unit's
  `LimitNOFILE` of 65536) and 256 management connections. Before, it set none,
  so neither listener had a connection ceiling, while the unit's comment said
  it did. The derived `notify_pending_max` default follows the ceiling to
  180000. A `Register` or inventory report that arrives while the gateway's
  upstream client is restarting is now answered `UNAVAILABLE` (retry) instead
  of `INTERNAL`. The upgrade guide gains a row for this release's gateway
  changes, including the stop timeout a supervisor of your own must allow (more
  than `shutdown_flush_budget_ms`, 20 s by default; Docker's default is 10 s)
  and that deleting a pinned certificate file no longer withdraws the pin.
