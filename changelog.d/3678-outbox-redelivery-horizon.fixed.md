- **A scheduled run's retry can no longer re-execute a command the agent has already forgotten.**
  The command outbox re-sends a stable command ID on retry, and an agent absorbs the repeat only
  while that ID is still among its most recent 20,000 completed commands. The server now records
  the fleet-wide dispatch count before a run's first send and refuses a retry once that count has
  advanced by 10,000 (half the agent's memory): the run is marked failed with the note
  `redelivery_horizon_exceeded`, a `failure` `command.outbox_delivered` audit event is written, and
  `yuzu_server_command_outbox_deliver_horizon_exceeded_total` rises. The run is not cancelled, since
  an earlier attempt may already have executed. If the dispatch count cannot be read, the run is held
  and retried on the next cycle (`yuzu_server_command_outbox_deliver_degrade_total` rises). The
  limit counts commands, not time, so a run stuck on a quiet fleet is not ended by it; the time and
  retry-count caps remain open under #4167. New schema: `execution_tracker` migration 9 and
  `command_outbox_store` migration 4, both additive. A run still pending across the upgrade is
  measured from its first attempt after the upgrade.
