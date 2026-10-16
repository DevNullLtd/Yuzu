# Resource Ledger — macOS Endpoint Security development bundle

## Foundation PR integration

The original range below is historical. The foundation PR reapplies that work on
`1972d3e2a8c0beec9c71a4aa0fc2492d2619b4e1`, through `6eb78e12e` before the
developer-check/runbook additions. The integrated C++ ownership inventory is below:
the updater decision, existing-verifier CLI, and loopback test are carried forward;
no Spark/Guardian worker ownership or consumer selection changes are introduced.
Review/validation on the integrated source is recorded separately in the PR;
the prior governance fragment does not certify the rebase. The Python smoke
checker owns bounded subprocesses via `subprocess.run` and its marker directory
via `TemporaryDirectory`; it never starts or owns the installed daemon.

## Original implementation inventory

Reviewed C++ range: `d295db964b0e3fa3fec7573f9fc9141c8c41f389..9c702a3d7de12eb934c75cf8be67fb4332f2780c`.
This ledger covers the modified C++ updater path and the new loopback lifecycle
test. A later C++ change must extend or replace this immutable range as part of
its governance review. Packaging-script subprocesses are Python or shell
resources and are outside the C++ resource-ledger inventory.

| Resource | Owner | Acquisition | Release / transfer | Failure cleanup |
|---|---|---|---|---|
| Updater filesystem maintenance decision | `Updater` owned by `Agent` shared pointer | `Agent::run()` constructs and retains the existing updater | No new raw resource; `perform_startup_maintenance()` calls existing rollback/cleanup only when enabled | Disabled mode returns before any updater filesystem mutation; existing enabled-mode error handling is unchanged. |
| Loopback gRPC server | `LoopbackHarness::server` (`std::unique_ptr<grpc::Server>`) | `grpc::ServerBuilder::BuildAndStart()` after registering the member service | Destructor calls `Shutdown(deadline)` then `Wait()` before members are destroyed; no ownership transfer | Null server is asserted before agent construction. Destructor tolerates an empty server. |
| gRPC service / callback context | `LoopbackHarness::service` value member | Registered by address with its owning `ServerBuilder` during harness construction | Harness declaration order keeps `server` destroyed before `service`; server is shut down/waited first | If build/start returns null, no server owns the service and the test fails before creating the agent. |
| Agent runner thread and global subprocess cancellation state | `AgentRunner` owns a `std::thread` and borrows the longer-lived agent | Snapshots the cancellation flag, starts `Agent::run()` after successful `Agent::create()` | Non-copyable/non-movable owner stops the agent, joins, then restores the prior cancellation flag; no dependency on Apple libc++ `jthread` availability | Catch2 assertion/timeout unwinding invokes the same stop/join/reset path; thread construction failure starts no owned thread; no detach or cancellation leakage to later tests. |
| Temporary plugin/data paths and SQLite files | `yuzu::test::TempDir` | Creates a `yuzu_test_`-prefixed test directory | RAII destructor removes the task-owned directory after agent/thread teardown | Construction failure prevents agent startup; no shared fixed path. |
| Executable-adjacent OTA sidecar test lock | non-copyable `ExecutableSidecarLock` test value | `open(O_CREAT|O_RDWR)` plus advisory `flock(LOCK_EX)` on the test executable's parent | Destructor unlocks and closes the single fd after `FileBackup` restoration | A failed open fails the test before sidecars are touched; the lock serializes the unavoidable fixed `.old`/marker probe across shared-identity processes. |
| Executable-adjacent OTA sidecar bytes | non-copyable `FileBackup` test values, with private uniquely named sibling backup directory | Copy each original regular file to disk before writing test sentinels; reject symlinks/non-regular files | Restore by same-filesystem rename, then remove the empty backup directory; idempotent explicit/destructor restoration | Snapshot failure leaves the original untouched. Failed sentinel write is detected on close and owners restore during unwind. Failed restore retains the on-disk original for recovery and terminates visibly on destructor failure; no claim of power-loss durability. |
| Lifecycle synchronization state | `OtaDisabledLifecycleService` mutex, condition variable and value fields | Service construction | Value destruction after gRPC server shutdown | Every predicate update is under `mu` and followed by `notify_all`; wait predicate reads under the same mutex. |

No new HANDLE, raw socket, `FILE*`, SQLite handle/statement, OpenSSL object,
mapped library, allocated C string, C-ABI-owned buffer, `release()` transfer, or
cast is introduced in the C++ diff. The one new test-only fd is owned above. The packaging-only
`--verify-plugin-signature` CLI plumbing calls the existing verifier and owns no
new OS resource.
