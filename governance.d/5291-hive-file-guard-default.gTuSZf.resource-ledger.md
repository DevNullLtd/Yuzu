# Resource Ledger -- TAR mapped-drive history: hive-mount worker, module pin and retry state

Range: `08dd782bc..HEAD` (branch `fix/hive-file-guard-default`, the review-fix round of PR #6311;
the earlier rounds of the PR changed `with_user_hive`'s default and are recorded in the finding
ledger beside this file).

## Summary

The mapped-drive history walk (`enum_registry_outbound_history`, Windows only) mounts each logged-out
profile's `NTUSER.DAT` inside `bounded_call_ex`, which runs the mount on a **detached** worker thread
and returns on a timeout without joining it. This round adds one deliberately unreleased resource (a
module pin), one counter that tracks the workers, and a pure outcome flag; it adds no fd, handle,
socket, `FILE*`, subprocess or temp path, and no RAII wrapper is bypassed.

## Table 1 -- owned resources

| # | Resource | Owner | Acquired | Released | Failure / early returns |
|---|---|---|---|---|---|
| 1 | a reference on the TAR module (`GetModuleHandleExW` with `GET_MODULE_HANDLE_EX_FLAG_PIN`) | the OS loader, for the life of the process | `pin_plugin_module()`, once (a function-local `static const bool`), on the dispatching thread before the first `bounded_call_ex` | never, by design: the thing it protects is a thread nothing can join. Manual (non-RAII) by necessity | a failed pin returns false, is cached for the process and logged once at error level; no worker is spawned, so no hive is read (live-hive profiles included) until the agent restarts; every requested profile is recorded `attempted=false` (token `pin_failed`) and stays pending |
| 2 | the detached mount worker thread, one per profile | the thread itself, through its closure (a move-only callable handed to `bounded_call_ex`): `sid`, `path`, `pname`, `cap_baseline` by value, plus `bounded_call_ex`'s `shared_ptr<State>`; ownership transfers to the thread at spawn and never returns | `bounded_call_ex` (spawn) | thread end; the outstanding-call slot is released when the callable is destroyed | a spawn or setup failure becomes `Rejected` (nothing ran, not an attempt); a timeout abandons the thread (the caller never touches it again); an exception out of the closure is swallowed by `bounded_call_ex`, the caller waits the full bound and sees `TimedOut` (pre-existing behaviour of the primitive; the guard in row 3 still unwinds) |
| 3 | `g_mount_workers_in_flight` (a plugin-static `std::atomic<int>`) and its `MountWorkerGuard` | the guard, an automatic object at the top of the worker closure | the guard's constructor, when the closure starts | the guard's destructor, when the closure returns (before the result is published) | an abandoned worker stays counted until it really returns, which is how a later walk learns not to mount behind it |
| 4 | side effects a stuck worker keeps | the worker | `with_user_hive` | when the worker returns | the process-wide offline-hive mutex (every other OFFLINE `with_user_hive` caller queues behind it; live-hive reads do not take it); `SeBackup`/`SeRestore` enabled on the process token (`PrivilegeScope` restores on return); one of this DLL's 64 outstanding-call slots (the counter is per module); and, for a worker stuck after a successful `RegLoadKeyW`, the loaded hive and that profile's `NTUSER.DAT` lock |

## Table 2 -- borrowed state and callback contexts

| Holder | Borrows | Lifetime |
|---|---|---|
| the mount worker closure | nothing: four values copied in; it writes only into its own `BoundedProfileRead` | the closure; no pointer to `TarPlugin`, `MapDriveHistory`, `profiles` or the database is captured |
| `ScopedOfflineHiveLock` (inside `with_user_hive`) | `offline_hive_mutex()` and spdlog, both in `yuzu_agent_core` | never unloaded; the worker's tail runs in pinned TAR code and non-unloaded agent-core |
| the walk's gate | `g_mount_workers_in_flight`, read once at walk start on the dispatching thread | a plugin static in pinned memory |

## Why a pin and not a join

`TarPlugin::shutdown` cannot join a worker blocked in `RegLoadKeyW` (no cancel exists), and a worker
that completed still destroys its plugin-resident closure after publishing the result, so a pin taken
only on a timeout left that tail exposed (found in adversarial review). The agent-core placement
`dism_bounded_call.hpp` uses was offered as the alternative and declined for this round (a redesign);
other plugins (for example `discovery`, `power_health` and `printing`) call `bounded_call` from plugin code and carry the same residual.


## Accepted residuals (recorded, with the reviewer's adjudication in the finding ledger)

The TAR DLL stays loaded until the process exits (it is loaded for the agent's lifetime anyway; a
pinned DLL cannot be replaced on disk, but the OTA updater replaces the agent executable and restarts
the process, and the installer stops the service first). Rows 3 and 4 above for a worker stuck for
days. While a worker is stuck, no further hive is read (the walk gate, row 3), so no profile is
charged and none is abandoned: a head profile whose worker never returns holds every profile behind
it pending until the worker returns or the agent restarts (each restart gives the head profile one
more attempt, so it is abandoned after seven restarts). The delay is bounded only by that, which is
why the stuck cases are logged at warning level on every run.
