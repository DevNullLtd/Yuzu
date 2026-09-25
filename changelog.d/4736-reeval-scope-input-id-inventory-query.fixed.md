- **The #4306 re-eval target-erasure fix now also covers `from-inventory-query`.** `POST
  /api/v1/result-sets/from-inventory-query` and MCP `create_result_set_from_inventory_query`
  also accept a caller-supplied, owner-checked `parent_id` but previously never recorded the
  `scope_input_id` marker the #4306 fix relies on. Inert today only because `re-eval`'s
  `source_kind` allowlist already refuses `inventory_query`-sourced sets before the parent-gone
  guard ever runs — but both routes now persist `scope_input_id` too, matching the other three
  creation paths, so the protection holds even if re-eval's supported-kind set is ever widened.
