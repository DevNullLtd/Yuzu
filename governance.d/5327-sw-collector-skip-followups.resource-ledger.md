# Resource Ledger — #5327 (installed-software collector skip follow-ups)

Range `b123c55c0..HEAD` (col-1..col-3). A Resource Ledger is required for a C++ diff (policy floor).

## Production code (`agents/core/src/sync_scheduler.{hpp,cpp}`, `sync_source_installed_software.cpp`, `plugin_loader.cpp`, `agent.cpp`)

No new fd, HANDLE, SOCKET, `FILE*`, sqlite handle, OpenSSL object, C string, mapped library, temp path,
subprocess or thread.

| resource | owner | acquired | released | transfer | failure cleanup |
|---|---|---|---|---|---|
| `std::shared_ptr<std::string> last_reason`, captured by the `collect` lambda and the `skip_reason` std::function | `SyncSource` (both closures hold a copy) | `make_installed_software_source`, once | with the source, i.e. the lifetime of `sources_` | none; shared by the two closures only | shared_ptr RAII. No cross-thread access: `collect` and `skip_reason` both run on the ticking thread (`note_skip` is called from `tick()` right after `collect`) |
| `State::skip_streak` (int), `State::last_skip` (std::string) | `SyncScheduler::states_[i]`, ticking thread | `load_state` (read from KV, streak clamped to `[0, INT_MAX]`) / `note_skip` | destroyed with the scheduler | none; plain values persisted via `kv_set_` | `save_state` writes `skip_streak`, `last_skip`, then `next_fire`, so an interrupted save never advances `next_fire` ahead of the skip fields (the stale `next_fire` makes the next tick retry). A kill between the `skip_streak` and `last_skip` writes can leave a streak with no reason, so `emit_sync_skip_tags` publishes no skip tags until that retry; inventory is unaffected |
| `emit_sync_skip_tags` KV reads on the heartbeat thread (transient `std::optional<std::string>` per key) | the call frame | `get_fn(kv_key(...))` | end of each loop iteration | none; copies assigned into the tag map | the existing shared `KvStore` connection (FULLMUTEX) is used; no new handle. A missing, malformed or over-long value is skipped, never thrown. The call sits inside the existing `try`/`catch` of the plugin-tag bridge |
| `seen_names` (`std::unordered_set<std::string>`) in `PluginLoader::scan` | the `scan` stack frame | declared before the directory walk | scan return | none | scan-scoped; destroyed on any exit, including an exception |
| refused duplicate `PluginHandle` | the loop-local handle in `scan` | dlopen earlier in the same iteration | dropped at `continue`, exactly as a reserved-name handle is: the destructor dlcloses the library | none (not moved into `result.loaded`) | `init` was never called, so no `shutdown` is owed; the rejection is recorded in `result.errors` with `kDuplicateNameReason` |

Threads: none created. Callback contexts: `skip_reason` is invoked only from `SyncScheduler::tick()` (via
`note_skip`); it captures only the `last_reason` shared_ptr, so it cannot dangle. The heartbeat thread reads the
`__sync__` KV, never `states_` or `last_reason`.

## Test code (`tests/unit/test_inventory_sync.cpp`, `test_inventory_sync_action_table.cpp`, `test_plugin_loader.cpp`)

Pure-function and in-memory fixtures: scheduler tests inject `kv_get_`/`kv_set_` map lambdas and a fake clock;
the collector tests inject descriptors; the duplicate-name loader test copies a fixture plugin twice under a `yuzu_test_dup_plugin_` temp
directory, clears `result.loaded` (dlclose) and then `fs::remove_all`s it at the end of the case. No new process, socket or long-lived handle.
