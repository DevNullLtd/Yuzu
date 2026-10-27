- **Gateway: upstream permits follow the stream limit the server declares (#5695).**
  The gateway no longer assumes the server's HTTP/2 concurrent-stream limit (128 by
  default). The upstream channel reads `SETTINGS_MAX_CONCURRENT_STREAMS` from every
  connection the server opens (and every later change, RFC 9113 6.5.2), published as
  the new gauge `yuzu_gw_upstream_server_max_streams`. The gateway sets aside the 61
  streams its other lanes use (stream-status notifications, Guardian forwards,
  heartbeat flush) and, when the rest cannot hold the configured `register` and
  `inventory` permits, shrinks them in proportion (never below one each);
  `yuzu_gw_upstream_permit_limit` now shows the permits in force. At the C++ default
  of 128 nothing changes. A lower limit revokes no permit; new ones wait until fewer
  are held. A proxied call or replay that the gateway's HTTP/2 client refuses as
  `too_many_streams` is no longer a circuit-breaker failure: it waits for a permit
  again until its deadline, and is counted under
  `yuzu_gw_upstream_rpc_errors_total{code="too_many_streams"}` (it was `stream_error`).
  A server that allows fewer than 61 streams is logged as a warning. See "How the
  gateway sizes its upstream calls" in the gateway manual.
