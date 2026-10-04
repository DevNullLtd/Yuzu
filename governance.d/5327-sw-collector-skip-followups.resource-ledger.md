# Resource Ledger — #5327 (installed-software collector skip follow-ups)

Range `b123c55c0..fced3c772` plus the gate-fix commits that follow it (the governance gate re-pins the final
head). A Resource Ledger is required for a C++ diff (policy floor).

## Production code (`agents/core/src/sync_scheduler.{hpp,cpp}`, `sync_source_installed_software.cpp`, `plugin_loader.cpp`, `agent.cpp`)

No new fd, HANDLE, SOCKET, `FILE*`, sqlite handle, OpenSSL object, C string, mapped library, temp path,
subprocess or thread.

| resource | owner | acquired | released | transfer | failure cleanup |
|---|---|---|---|---|---|
| `std::shared_ptr<std::string> last_reason`, captured by the `collect` lambda and the `skip_reason` std::function | `SyncSource` (both closures hold a copy) | `make_installed_software_source`, once | with the source, i.e. the lifetime of `sources_` | none; shared by the two closures only | shared_ptr RAII. No cross-thread access: `collect` and `skip_reason` both run on the ticking thread (`note_skip` is called from `tick()` right after `collect`) |
| `State::skip_streak` (int), `State::last_skip` (std::string) | `SyncScheduler::states_[i]`, ticking thread | `load_state` (read from KV, streak clamped to `[0, INT_MAX]`) / `note_skip` | destroyed with the scheduler | none; plain values persisted via `kv_set_` | `save_state` writes `skip_streak`, `last_skip`, then `next_fire`, so an interrupted save never advances `next_fire` ahead of the skip fields (the stale `next_fire` makes the next tick retry). A kill between the `skip_streak` and `last_skip` writes can leave a streak with no reason, so `emit_sync_skip_tags` publishes no skip tags until that retry; inventory is unaffected |
| `emit_sync_skip_tags` KV reads on the heartbeat thread (transient `std::optional<std::string>` per key) | the call frame | `get_fn(kv_key(...))` | end of each loop iteration | none; copies assigned into the tag map | the existing shared `KvStore` connection (FULLMUTEX) is used; no new handle. A missing, malformed or over-long value is skipped, never thrown. The call sits inside the existing `try`/`catch` of the plugin-tag bridge |
| the `get_fn` callback passed to `emit_sync_skip_tags` (a `[this]`-capturing lambda converted to a temporary `std::function`) | the heartbeat loop's call frame | constructed at the call | destroyed with the full expression, after the call returns | none | synchronous: the callee runs entirely inside the call, so the captured `this` cannot dangle; it only reads `kv_store_` (KvStore's own mutex); inside the existing `try`/`catch` |
| `std::shared_ptr<SyncScheduler> sched`, the heartbeat thread's co-owner copy | the heartbeat loop iteration's scope | copy of `sync_scheduler_` taken under `sync_sched_mu_` | end of that scope | none (the `__sync__.now` handler takes the same copy) | RAII. A late `~SyncScheduler` on this thread only destroys captures: no plugin call, no lock held. `source_names()` reads only `sources_`, which is append-only and complete before the scheduler is published, never `sender_` (which captures the sync thread's gRPC stub) |
| `seen_names` (`std::unordered_set<std::string>`) in `PluginLoader::scan` | the `scan` stack frame | declared before the directory walk | scan return | none | scan-scoped; destroyed on any exit, including an exception |
| refused duplicate `PluginHandle` | the loop-local handle in `scan` | dlopen earlier in the same iteration | dropped at `continue`, exactly as a reserved-name handle is: the destructor dlcloses the library | none (not moved into `result.loaded`) | `init` was never called, so no `shutdown` is owed; the rejection is recorded in `result.errors` with `kDuplicateNameReason` |

Threads: none created. Callback contexts: `skip_reason` is invoked only from `SyncScheduler::tick()` (via
`note_skip`); it captures only the `last_reason` shared_ptr, so it cannot dangle. The heartbeat thread reads the
`__sync__` KV and `sources_` (through `source_names()`), never `states_` or `last_reason`.

## Test code (`tests/unit/test_inventory_sync.cpp`, `test_inventory_sync_action_table.cpp`, `test_plugin_loader.cpp`)

Scheduler tests inject `kv_get_`/`kv_set_` map lambdas and a fake clock; the collector tests inject descriptors. Two
tests acquire real resources, both RAII:

| resource | owner | acquired | released | transfer | failure cleanup |
|---|---|---|---|---|---|
| mapped plugin libraries: `PluginHandle::load` of `installed_apps`, `pkg_inventory` and `windows_optional_features` from the build root (`MESON_BUILD_ROOT` when set, else the working directory `meson test` runs in), one load per table row (four in all) | the loop-local `std::expected<PluginHandle, LoadError>` in the descriptor-pin case | each iteration of the pin loop | end of the iteration: `~PluginHandle` dlcloses | none | RAII; a failed `REQUIRE` unwinds the scope. `init` is never called, so no `shutdown` is owed |
| duplicate-name scratch directory holding two copied plugin binaries (`yuzu_test_dup_plugin_` prefix) and the dlopen handle `scan` returns for the winner | `yuzu::test::TempDir tmp`, declared before `result` (and `result.loaded`) | the case body | scope exit: `result` is destroyed first (dlclose), then `tmp` removes the directory | none | RAII on both, so a failed `REQUIRE` still removes the directory |

No new process, socket or long-lived handle.

**Adjudications recorded:** none required — no manual (non-RAII) resource cleanup exists in this diff.
