- **A scheduled run's retry can no longer re-execute a command the agent has already forgotten.**
  The command outbox re-sends a stable command ID on retry, and an agent absorbs the repeat only
  while that ID is still among its most recent 20,000 completed commands. The server now records its
  dispatch count before an occurrence's first delivery attempt and refuses a retry once that count has
  advanced by 10,000 (half the agent's memory): the occurrence is marked failed with the note
  `redelivery_horizon_exceeded` (`redelivery_sequence_regressed` if the count went backwards), a
  `failure` `command.outbox_delivered` audit event is written, and
  `yuzu_server_command_outbox_deliver_horizon_exceeded_total` rises. The failed occurrence may have
  executed once or may never have been sent, and its execution row is not cancelled by this step. A
  first attempt that reached no agent does not start the count. If the dispatch count cannot be read,
  occurrences are held and retried on the next cycle
  (`yuzu_server_command_outbox_deliver_hold_cause_total{cause}` and
  `yuzu_server_command_outbox_deliver_degrade_total` rise). The count is an estimate: it is
  fleet-wide and counts a Guardian, asset-tag or sync push once per target, so a very large push can
  end a waiting occurrence early; and dispatch records that fail to write on a different server
  replica are not counted, so there the limit can trip late. It does not limit time, so an
  occurrence stuck on a quiet fleet is not ended by it; the time and retry-count caps remain open
  under #4167. New schema: `execution_tracker` migration 9 and `command_outbox_store` migration 4,
  both additive.
