- **The gateway now reports whether it is keeping up, and three alerts say when
  to act.** New metrics on the gateway's `/metrics` (port 9568): the mailbox
  length and queue wait of the nine processes every agent's traffic passes
  through (`yuzu_gw_process_mailbox_len`, `yuzu_gw_process_queue_wait_seconds`),
  connections per listener against `max_connections`
  (`yuzu_gw_listener_connections`, `yuzu_gw_listener_max_connections`), ports
  against the port and open-files limits (`yuzu_gw_beam_ports`,
  `yuzu_gw_beam_port_limit`, `yuzu_gw_beam_fd_limit`), the run queue, the
  management listener's calls in flight, the router's fan-outs in flight, and
  connections the HTTP/2 server closed itself by reason
  (`yuzu_gw_grpc_connections_closed_total`: `idle_timeout`,
  `enhance_your_calm`, `protocol_error`). They are sampled every 10 s at a cost
  that does not grow with the fleet. New alerts, each naming the action:
  `YuzuGatewayListenerNearConnectionCeiling`,
  `YuzuGatewayFileDescriptorsNearLimit` and `YuzuGatewayProcessBacklogged`.
  `yuzu_gw_beam_scheduler_util` now counts the normal schedulers only (it read
  about 0.3 on a fully busy gateway). Families that used to appear only after
  their first event (agent connects and disconnects, the VM gauges, cluster
  peers, Guardian forward drops) now exist at 0 from start. The warning for a
  message to a stream that had already ended is limited to one line per second
  for the whole gateway, not per connection (a registration storm wrote one per
  agent). Every gateway metric is listed in the metrics manual, and a test
  scrapes a started gateway to check that each declared metric is exported and
  documented and that every alert reads a metric the gateway exports.
