# Resource Ledger - CI PR2 test hot spots (#4882, #2600)

Run: `governance.d/4882-ci-test-hot-spots.GMJNpC.jsonl`
Range: `5f4064fb4..4c821ff21` (the branch's own commits 614d837b2..a477db1cc plus the gate-fix commits and the origin/dev merge 8d1caf981).

## Summary

This range introduces **no new or modified fd / HANDLE / SOCKET / `FILE*` / `sqlite3_stmt*` / `sqlite3*` /
OpenSSL object / BCrypt handle / allocated C string / mapped library / temp path / subprocess.** The server
changes are eight test-only `*_for_test` seams plus one ownership move; the rest is test code and CI wiring.

## Ownership

| Item | Owner | Acquired | Released | Failure cleanup |
|---|---|---|---|---|
| `McpServer::posture_cache_` (`shared_ptr<PostureCache>`) | the McpServer member and the handler lambda's copy (two owners) | member default initializer at construction; `build_handler` copies it into the lambda | at McpServer / handler destruction; the lambda uses only its copy, never the member through `this` | none; no fallible acquisition |
| `PostureCache::mtx` | inside `PostureCache` | with it | with it | n/a; unchanged locking (two scopes in the handler, one in `age_posture_cache_for_test`) |
| `RbacStore::age_refresh_state_for_test` | takes `cache_mtx_`, then `breaker_mtx_`, in two sequential scopes | scope entry | scope exit (`lock_guard`) | never nested; production never nests the two either |
| `AuthManager::idle_session_for_test`, `lapse_elevation_for_test` | `mu_` (`unique_lock`) | held across find and mutate | scope exit | early return on unknown token |
| `AuthRoutes::expire_mfa_pending_for_test` | `mfa_pending_mu_` (`lock_guard`) | scope entry | scope exit | no-op on unknown token |
| `AgentRegistry::expire_presence_cache_for_test` | `presence_cache_mu_` (`lock_guard`) | scope entry | scope exit | n/a |
| `AnalyticsEventStore::drain_once_for_test`, `drain_running_for_test` | no lock taken: a caller-thread `drain_batch()` (its own Postgres advisory transaction lock excludes a concurrent drain) and an unsynchronised `joinable()` read | n/a | n/a | documented: not to be called while the drain thread runs |
| Tar test writer thread (`test_tar_aggregator.cpp`) | existing RAII `Joiner` | test scope | every exit path, including a failed `REQUIRE` or a throw from `run_retention` | unchanged; `kMaxProbeWrites` bounds the loop, the 1 ms park still honours `stop` |

No thread, callback context or raw resource API was added. Every seam has zero callers outside tests.
Confirmed independently by cpp-safety (Gate 3, no findings), security-guardian and authdb. Sanitizer coverage:
TSan, already in the Linux sanitizer legs; ASan/UBSan add nothing new.
