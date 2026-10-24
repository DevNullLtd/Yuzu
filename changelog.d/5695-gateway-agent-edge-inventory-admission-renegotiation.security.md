- **Gateway agent listener: `ReportInventory` needs a session, and TLS clients can no longer
  renegotiate.** The gateway now forwards an agent's inventory report only for a session it holds
  on the calling connection, the same check Heartbeat already applies. Before this, any peer that
  could open a TLS connection to `:50051` could send inventory reports without registering, hold
  every upstream inventory permit and wait-queue slot, and keep queued reports in memory. A refused
  report gets gRPC `NOT_FOUND` (`unknown session`) and is counted in the new
  `yuzu_gw_inventory_rejected_total{reason}`. Registered agents are not affected: they send
  inventory on the connection that opened their session, and the agent retries a failed report on
  its next sync tick. Every gateway TLS listener (agent and management) now refuses a
  client-initiated renegotiation (`client_renegotiation` false, `secure_renegotiate` true), so a
  peer can no longer make the gateway repeat full handshakes on one connection. Neither setting can
  be changed in configuration, and a listener whose `listen.socket_opts` sets either one refuses
  to boot.
