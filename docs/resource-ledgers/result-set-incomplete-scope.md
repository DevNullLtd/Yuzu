# Resource Ledger: result sets that are not ready or incomplete

New or modified owned resources in `server/core/src/` (`result_set_store.cpp`,
`agent_registry.cpp`, `server.cpp`, `execution_tracker.cpp`, `agent_service_impl.{hpp,cpp}`) and
their unit tests. No thread, socket, descriptor, callback, `FILE*` or SQLite handle is added.

## Resources

### Persisted column `result_sets.agents_unanswered`
- **Site:** migration v5 in `result_set_store.cpp`, written by `ResultSetStore::materialize` in the
  same transaction that writes the membership, `device_count` and `agents_failed`.
- **Owner type:** the existing `result_set_store` schema; the column lives and dies with its row.
- **Release point:** the row's own deletion.
- **Transfer:** never. Read back into `ResultSet::agents_unanswered` by value.
- **Failure cleanup:** a failed update rolls back with the membership insert; the migration is
  idempotent (`IF NOT EXISTS`).

### `OwnedMembers` and the completeness list
- **Site:** `member_set_owned` returns an `OwnedMembers` value (a member set plus a `bool`);
  `AgentRegistry::evaluate_scope_impl` holds a local `std::vector<std::string>` of the set ids whose
  use depends on completeness.
- **Release point:** scope exit.
- **Failure cleanup:** RAII only.

### Persisted column `agent_exec_status.response_dropped`
- **Site:** migration v10 in `execution_tracker.cpp`, written by `upsert_agent_status_once` in the
  same transaction and the same statement as the agent's status, before the outbox append (the
  outbox contract is unchanged: the event payload does not carry it).
- **Owner type:** the existing `execution_tracker` schema; the column lives and dies with its row.
- **Release point:** the row's own deletion; a later terminal write for the same agent replaces it.
- **Transfer:** never. Counted by `ExecutionTracker::count_response_dropped` (a read-only count
  under its own bounded read lease; `nullopt` on any failure), called only by the result-set fill
  pass once an execution is terminal or its set has timed out.
- **Failure cleanup:** a failed upsert rolls back with the status; the migration is a
  constant-default `ADD COLUMN`.

### Completeness inherited from a parent set
- **Site:** `CreateRequest::agents_failed` / `agents_unanswered`, set by `inherit_completeness` at
  every producer whose members come from the parent's (the inventory producers and the three
  asynchronous ones, REST `run_async` and MCP `rs_run_async`) and persisted by `insert_row_impl` in
  the same insert as the row; `materialize` adds the fill's own counts to them in its
  status-guarded update. The fill pass never reads the parent.
- **Owner type:** plain integers on a request or local value; no handle.
- **Release point:** scope exit.
- **Failure cleanup:** none needed: the counters ride the existing insert and update statements.

### `AgentServiceImpl::unverified_frames_` (bounded in-memory registry)
- **Site:** member of `AgentServiceImpl`, type `UnverifiedFrameRegistry`
  (`unverified_frame_registry.hpp`). Written by `note_unverified_frame` at the two RUNNING ingest
  sites (Subscribe and gateway) only when the frame's provenance lookup failed
  (`ProvenanceOutcome::kLookupDegraded`), and by `notify_exec_tracker` when a frame the store did
  not keep could not be recorded on a tracker row either (`update_agent_status` returned false),
  even when a marker, remembered command or the latch already reports the pair; read without
  erasing by `unverified_frame_seen` at the two terminal ingest sites; an entry is erased by
  `notify_exec_tracker` only after `ExecutionTracker::update_agent_status` wrote a row carrying a
  true `response_dropped`.
- **Owner type:** owned by value by the service; `std::map`/`std::set` entries keyed by the exact
  agent id and a 64-bit digest of the command id salted with a random per-process value (in
  process only), plus a `std::mutex`, no thread, no callback, no handle.
- **Bound:** 64 entries per agent, 4,096 entries in all, 1,024 agent markers and 1,024 remembered
  commands. An entry and a marker hold the agent id, which Register bounds to 256 bytes
  (`auth::kMaxAgentIdLength`, asserted equal to the registry's `kMaxAgentIdBytes`); a longer id is
  never stored, sets the latch instead and is counted as an eviction. Held memory is bounded, about 4 MiB worst case with every
  structure full and every agent id at 256 bytes (an estimate from allocation sizes measured on one
  platform). A new entry past an
  agent's own cap evicts that agent's oldest entry and marks the agent (every pair of a marked agent
  reads as not fully stored; a flooding agent affects only its own pairs); past the global cap the
  oldest entry is evicted and its command remembered (every agent of it reads as not fully stored).
  When the marker set or the command set is full, the oldest member is dropped and one latch is set
  under which every pair reads as not fully stored: only the latch and a remembered command reach
  other agents. Each eviction is counted as
  `yuzu_server_response_ingest_dropped_total{reason="unverified_registry_overflow"}`. Entries last
  one hour; markers, remembered commands and the latch last for an hour after the last record they
  covered (set again on each eviction; expired on every `note` and `contains`, against
  `steady_clock` seconds). `note` inserts into its three indexes or none, sets a marker or
  remembers a command before it erases the entry that stands for it, and refreshes an existing
  marker or remembered command in place (the re-key allocates nothing, and the id is copied only
  when it is new), so an allocation failure leaves no orphan and loses no record. After such a
  failure the registry can hold more than 4,096 entries (one more per failed `note`) until the
  next inserting `note` evicts back to the cap (a note for a pair already held does not trim).
- **Lock:** its own `mu_`, held only for the map operations; no other lock is taken under it and it
  is never held across I/O.
- **Release point:** each entry on a recorded flag, expiry or eviction; the whole registry with the
  service. The detached gateway-forward threads that reach `process_gateway_response` are NOT
  bounded by the service's lifetime: they are the known #3279 residual (the gateway-forward note
  near the top of `agent_service_impl.cpp`, above `audit_registry_frame`), and this member shares
  that residual with `this`, `metrics_` and every other member those threads touch.
- **Failure cleanup:** RAII only: two RAII scope guards (in `note` and in `AgedSet::remember`),
  dismissed on success, undo a half-inserted index node when an allocation throws; nothing
  persists.

### Borrowed `const ForensicsPluginSet*` on the result-set producers
- **Site:** REST `run_async` (`rest_api_v1.cpp`) captures the route's `forensics_plugins` pointer by
  value; MCP `rs_run_async` (`mcp_server.cpp`) reads `forensics_plugins_` through its `this` borrow.
  Both pass it to `plugin_may_seed_result_set` (`result_set_members.hpp`) to refuse a Forensics-tier
  source before any dispatch.
- **Owner type:** borrowed, never owned and never released by either surface. The pointee is
  `ServerImpl::forensics_plugin_set_` (`std::optional<ForensicsPluginSet>`), derived once in the
  constructor; the server refuses to start without it, and it is wired before the routes register.
- **Lifetime:** `forensics_plugin_set_` is declared before `web_server_`, `rest_api_v1_` and
  `mcp_server_` in `ServerImpl`, so it is destroyed after both surfaces and after the HTTP server
  whose handler threads run the lambdas; it is immutable after construction, so no lock is needed.
- **Failure cleanup:** none; a null pointer (an unwired test harness only) refuses nothing.

### Function-local `static RefusalLogThrottle` log limiters
- **Site:** `unreadable_log` in the result-set fill lambda (`server.cpp`) and `marker_log` in
  `AgentServiceImpl::note_unverified_frame` (`agent_service_impl.cpp`).
- **Owner type:** function-local statics; a bounded map (at most 1,024 keys, its own mutex) of the
  last warn time per set id or agent id. Only the log line is limited; counters record every case.
- **Release point:** static destruction at process exit.
- **Failure cleanup:** none needed; a full map demotes the line, never grows.
