# Resource Ledger — quarantine follow-ups

Range: `a8a962f92..HEAD` (branch `fix/quarantine-followups`; base is the head of the PRQ.2 branch that follows #7530)

## Summary

No new fd, `HANDLE`, `SOCKET`, `FILE*`, `sqlite3*`, OpenSSL object, BCrypt handle, mapped library, subprocess or temp path in server or agent C++. The new owned state is: one durable row lease (the apply claim), a few stored callbacks, two in-memory sets, one new thread-free time budget, and on the installer side (Linux and macOS) two root-owned helper files written atomically (shell, not C++). Every new store method takes a bounded RAII pool lease that the existing store already uses.

## Table 1 — new owned state

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | Apply claim: durable row lease (`apply_gen`, `apply_claimed_at` on `quarantine_records`) | the `redispatch_stored_containment` call | `claim_apply` before the dispatch (generation + 1, stamped from the database clock) | a `ScopeExit` guard calls `release_apply_claim` for its own generation on every exit, including a non-`std::exception` throw | none | a failed release is logged; a claim never released (crash, failed release) stops counting after 120 s, judged on the database clock in the same SQL fragment at all four sites |
| R2 | `tool_deps.quarantine_owed_list_fn` (stored callback, captures `this`) | `McpToolDeps`, set in `ServerImpl` wiring (server.cpp) | at server wiring | with `ServerImpl` (same lifetime as `hw_quarantine_list_fn`) | none | unwired: `answer_unwired` fails closed (never an empty list) |
| R3 | `QuarantineContainmentReconciler::Deps::steady_now_fn` | `Deps` value inside the reconciler | production leaves it unset (falls back to `steady_clock`); tests set it | with the reconciler | none | tests capture a `FakeSteady` by reference: it must outlive the reconciler (the `Rig` owns both) |
| R4 | `detail::release_confirm_pause_hook()` (global `std::function`, test seam in `rest_api_v1`) | namespace-scope, read by the DELETE handler | tests set it | tests reset it (the `ReleasePollSeams` fixture saves and restores) | none | empty in production; documented as single-threaded and not synchronised: set only while no request is in flight |
| R5 | `heartbeat_due_` set and `cache_mu_` | the reconciler | `notify_agent_heartbeat` inserts under `cache_mu_` | `drain_heartbeat_due` moves the set out under `cache_mu_` and works on a local copy; devices not started (cap or time budget) are merged back under `cache_mu_` | the local set is consumed one device at a time | on stop the remainder is dropped; the next heartbeat marks the device again |
| R6 | `unconfirmed_cache_` | the reconciler | rebuilt in `tick()` with no lock held | swapped in under `cache_mu_`; the old set is freed after the unlock | none | a failed rebuild leaves the previous cache |
| R7 | The two root-owned helper files: `yuzu-fw-helper` (iptables, nft and, on macOS, pf anchor load) and `yuzu-svc-helper` (systemctl on Linux, launchctl on macOS), at `/usr/local/sbin/` on Linux and `/Library/PrivilegedHelperTools/` on macOS | `scripts/install-agent-user.sh` `install_helper` (one routine for both helpers on both platforms) | temp file in the same directory (`mktemp`), written, `chown root:<root group>` (root / wheel), `chmod 0755`, `sh -n`, then `mv -f` (atomic); the directory itself is checked (refuse a non-root owner or other-writable mode, warn on group-writable); an interrupted run can leave one `.yuzu-*-helper.XXXXXX` temp file, which is harmless and removed only by the invocation that created it | `--uninstall` removes the sudoers file first, then both helpers | none | every failure path removes the temp file; the installer installs the helpers before the sudoers file and exits non-zero if one fails |
| R8 | The helper's `nft load` action: one read of the agent's staged rule file, then rebuilt ruleset text piped to `nft -f /dev/stdin` | the helper process (a short-lived root shell run per call) | `head -c <cap> < file` after the path-shape and file-type checks; the whole input is read and checked before anything runs | process exit | none | holds no temp file: nothing to clean up after a kill; any refusal prints the fixed `refused` line, exits 64 and runs nothing. The path checks are not atomic with the open, so the checks of the content are the boundary |
| R9 | The helper's `pf load` action (macOS): one read of the agent's staged anchor file, then rebuilt pf anchor text piped to `pfctl -a com.apple/000.yuzu_quarantine -f /dev/stdin` | the helper process (a short-lived root shell run per call) | same as R8: the whole input is read and checked before anything runs | process exit | none | holds no temp file; any refusal prints the fixed `refused` line, exits 64 and runs nothing |
| R10 | `PfLeg::access_` (`ToolAccess`, direct or helper) and the euid-keyed helper path constants (`kSvcHelperPathLinux`, `kSvcHelperPathMacos`, `kFwHelperPathMacos`) | the leg object built once by `make_leg` from `::geteuid() == 0` | at leg construction | with the leg | none | immutable after construction; a non-root agent always takes the helper, a root agent runs the tool directly; no presence probe |
| R11 | `::geteuid()` read in `services_plugin.cpp` `do_set_start_mode_*` (Linux and macOS only, behind `#if defined(__linux__) || defined(__APPLE__)`) | the call itself | per dispatch | n/a | none | a plain syscall, no resource |

## Table 2 — borrowed data and lifetimes

None new. `string_view`s in the new query helpers are consumed straight away by `to_text_array`.

## Table 3 — threads

No new thread. The reconciler thread (`quarantine_reconcile_thread_`) keeps its owner, stop flag and join in `stop()`; its sleep is now 1 s per pass (was 5 s x 4) with the drain every pass and `tick()` after 20 s of steady time. Shutdown latency improves from up to 5 s to up to 1 s plus one in-flight device. The test fixture `BlockedApply` owns one `std::thread`, joined in its destructor on every path.

## Table 4 — locks

`mu_` (entry state) and `cache_mu_` (heartbeat set and unconfirmed cache) are never held together; no store or dispatch I/O runs under either; `back_off` and `erase_if_current` take `mu_` themselves and are never called from inside a `mu_` scope.
