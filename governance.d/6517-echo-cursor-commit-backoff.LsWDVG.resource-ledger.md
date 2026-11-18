# Resource Ledger: 6517-echo-cursor-commit-backoff (range b7a9905e6..HEAD)

Run: `governance.d/6517-echo-cursor-commit-backoff.LsWDVG.jsonl`

No new or modified owned resource: no fd, HANDLE, SOCKET, FILE*, sqlite3 handle or statement, OpenSSL/BCrypt object, allocated C string, mapped library, subprocess, thread, callback context or temp path; no manual cleanup; no new casts. The change adds value-type state only. `CursorRetry` and `parse_tick_seconds` are `noexcept`.

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | `EchoPlugin::cursor_retry_` (`std::map<std::string, CursorRetry>`, echo_plugin.cpp) | the plugin object (member); guarded by `collect_mu_` | an entry is created by `operator[]` in the cursor loop of `collect_slow_impl` for an enabled source; updated by `note_failure` / `note_success` | erased by the collect-time disabled gate, and by the cursor source's enable/disable edge in `do_configure` (inside the existing `try`, before `on_enabled_changed`, under the `collect_mu_` that block already holds); destroyed with the plugin | none | in memory only; a restart starts empty (a retry at once); an exception in the cursor loop is caught by the arms that already exist there, each of which calls `back_off()` |
| R2 | `SourceHealthLedger::next_retry_` (`std::unordered_map<std::string, int64_t>`, echo_source_health.hpp) | the plugin's `health_` member; guarded by `health_mu_` (writer `note_next_retry`, reader `do_status`) | `set_next_retry` when a source is backed off | `clear_next_retry` from `note_next_retry(name, nullopt)`: on a returned tick, at the collect-time disabled gate, and at the `do_configure` edge; destroyed with the plugin | none | in memory only; lock order `collect_mu_` then `health_mu_`, the order the collect loop already uses |
| R3 | `RegistryCursorSource::commit_failing_since_` (`std::optional<std::int64_t>`, echo_registry_source.hpp) | the source object (member), touched only inside `collect()`, which the driver serialises | set to `now` when `insert_registry_events_and_cursor` fails | `reset()` after a commit succeeds; destroyed with the source | none | in memory only; a restart during the failures loses it, so no stall row is written (the restart gap row remains) |

Resources removed: none.
