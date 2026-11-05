- **Behaviour change — a scheduled run's retry is now refused once the server's dispatch count has
  advanced by 10,000 since its first attempt, instead of retrying indefinitely (an estimate; see the
  limits below).** The command outbox re-sends a stable command ID on retry, and an agent absorbs
  the repeat only while that ID is still among its most recent 20,000 completed commands, so an
  unbounded retry could re-execute a command the agent had forgotten. The occurrence is now marked
  failed with the note `redelivery_horizon_exceeded` (`redelivery_sequence_regressed` if the shared
  count went backwards, which means a database restore or a failover that lost writes), a `failure`
  `command.outbox_delivered` audit event is written, and
  `yuzu_server_command_outbox_deliver_horizon_exceeded_total` rises. **SIEM rules that treat that
  event's `failure` result as "reached no agents" need updating:** a dead-lettered occurrence may
  have reached some, or none. The failed occurrence may have executed once or may never have been
  sent, and an approval ticket it used stays spent, so check the agents' responses before running it
  again and re-approve if needed. Three new alerts ship in `yuzu-alerts.yml`: `YuzuOutboxHeld`,
  `YuzuOutboxStampFailing` and `YuzuOutboxDeadLettered`. A first attempt that reached no agent does
  not start the count. If the dispatch counts cannot be read the outbox holds: nothing is sent or
  failed, and the tick ends (`yuzu_server_command_outbox_deliver_hold_cause_total{cause}` rises).
  **Limits.** The count is an estimate, not a guarantee. It is fleet-wide and counts a Guardian,
  asset-tag or sync push once per target, so a very large push can end a waiting occurrence early.
  Dispatch records that fail to write are counted only by the server process that made them, so a
  different replica, or an earlier run of the same server that has since restarted or lost
  leadership, takes its count with it, and the limit can trip late. A command dispatched before the
  first attempt but delivered to the agent after it is not counted. Agents running without a
  working command-dedup store are not protected: they re-run every redelivery. It does not limit
  time: an occurrence stuck on a quiet fleet is not ended by it (the time and retry-count caps
  remain open under #4167). New schema: `execution_tracker` migration 9 and `command_outbox_store`
  migration 4, both additive.
