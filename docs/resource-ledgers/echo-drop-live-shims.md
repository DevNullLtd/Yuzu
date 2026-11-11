# Resource Ledger: Echo compatibility surfaces removed

No new or modified owned resource. The change deletes code in `agents/plugins/echo/src/`
(`echo_fold_schema`, `echo_schema_registry`, `echo_plugin.cpp`, `echo_db`,
`echo_db_v10_migration.cpp`, `echo_aggregator.hpp`) and `server/core/src/` (`agent_registry`,
`gateway_route_store`, `gateway_service_impl.cpp`, `dispatch_route_fallback.hpp`,
`dispatch_scope_ladder.hpp`, `server.cpp`, `device_routes`, `device_ui.cpp`,
`dashboard_routes.cpp`, `echo_process_tree`, `echo_tree_routes.hpp`). No thread, socket,
descriptor, callback, `FILE*`, SQLite handle or Postgres lease is added.

## Resources removed

- **`AgentRegistry` session flag `legacy_echo_wire_name`:** a plain `bool` on `AgentSession`, set
  at registration and read on every send. Removed with its readers; `send_to`, `send_to_all` and
  `send_via_directory` hand `cmd.wire()` to the queue or stream as they did before the flag.
- **Prepared statement in `EchoDatabase::open` and `EchoDatabase::stats`:** two `StmtPtr` reads of
  `echo_config.retention_days`, each scoped to its own block. Removed.
- **Postgres column `agent_routes.legacy_echo_wire_name`:** stays in the table (an applied
  migration is never edited); `register_fresh`, `lookup_route` and `lookup_routes` no longer write or
  read it. The upsert drops one bound parameter (`$3`).
- **`GatewayRouteFallback::legacy_wire_`:** a `std::unordered_set<std::string>` of agent ids, filled in
  `prepare()` from the directory rows and read by `legacy_wire_for()`. Removed with both.
- **Static set in `is_legacy_live_shim`:** a function-local `unordered_set` of sixteen names.
  Removed.

## Resources added

None.
