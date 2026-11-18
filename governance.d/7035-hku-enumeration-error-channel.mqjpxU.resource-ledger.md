# Resource Ledger -- HKEY_USERS enumeration error channel (#7035, HKU part of #7481)

Range: `b7a9905e6..HEAD` (branch `fix/win-hku-enumeration-error-channel`).

Supersedes row 10 of `echo-registry-offline-hives.oLh7Kq.resource-ledger.md` where it says the start-up sweep is ONE attempt per start without exception and that `enumerate_hku_subkeys` has no error channel. That ledger records an earlier run and is not edited.

## Summary

A failed or unstable listing of `HKEY_USERS` is no longer read as a complete list. The listing is one shared function, `yuzu::win::enumerate_hku_subkeys_checked()`, that walks `RegEnumKeyExW` and accepts a list only when two consecutive walks return the same names. Seven Windows callers refuse on its error, and the Echo start-up sweep keeps itself pending for one retry. No new handle type, thread, subprocess, temp file or persisted state; the one new piece of process state is a bool latch.

## Table 1 -- what each file adds or alters

| File | Change | Resources |
|---|---|---|
| `agents/shared/list_walk.hpp` (new) | `walk_enumeration` (moved from `echo_registry_parsers.hpp`) and `stable_walk` | None acquired; locals only (two vectors of names), no OS call, windows.h-free. |
| `agents/shared/win_profiles.hpp` | `enumerate_hku_subkeys_checked()`; the names-only `enumerate_hku_subkeys()` is deleted (no caller was left, and it read a failed listing as "no hives") | None. `HKEY_USERS` is a predefined handle, never opened or closed. Two to four `RegEnumKeyExW` walks per listing (two on a quiet host; at most four, then `unstable`), each walk one call per subkey plus the end call; one `wchar_t[256]` stack buffer per step. |
| `agents/plugins/echo/src/echo_registry_parsers.hpp`, `echo_registry_source.cpp` | `HiveSweepResult::listing_error`; `settle_sweep`; `OfflineMountTick::sweep_listing_retried`; one warning per failed listing in `run_pending_hive_sweep` | One `std::string` in the sweep result (returned by value from the bounded worker) and one bool latch, process lifetime, not persisted, no handle. The latch and the pending flag are touched only on the reader thread, after the worker returned. |
| `registry_win.cpp` (two sites), `installed_apps_plugin.cpp`, `licensing_win.cpp`, `autoruns_win.cpp`, `privacy_permissions_win.cpp`, `echo_mapdrive_collector.cpp` | refuse with `hku_list_incomplete` and a warning naming the cause | None. |
| `tests/test_hku_listing_pin_lexical.py` (new), `tests/meson.build` | source-text pin for the seven callers' refusal | None at run time; reads source files. |

## Row 10 replacement -- the start-up sweep of leftover `YUZU_HIVE_*` mounts

The sweep is ONE attempt per start EXCEPT when `HKEY_USERS` cannot be listed (a `RegEnumKeyExW` error, or a list on which no two consecutive walks agree). Then nothing is offered to the unload, `HiveSweepResult::listing_error` carries the cause, `sweep_pending` stays set and `sweep_listing_retried` permits exactly ONE retry, from the next `read_offline_hive_bounded` that finds the gate open (that is, before the NEXT offline mount, whichever one it is). Each failed listing logs one `hku_list_incomplete` warning naming the cause and whether a retry is left; the second failure completes the sweep. A host that never mounts a logged-off hive does not retry: the sweep stays pending to the end of the process, and what it missed waits for the next agent start or `reg unload`. A retained mount, a missing privilege and a caught exception still complete the sweep after one attempt. The listing runs inside the offline-hive lock and the 30 s bound.

## Accepted residuals

- **Two consecutive walks that each skip the same entry still agree.** A separate churn event inside both walks (the same entry skipped twice) is accepted as a complete list. This is far narrower than the case this change closes (a middle walk accepted on the strength of the walks around it) and does not depend on any probe of the key; the count-plus-last-write stamp was not measured and is not used.
- **A busy host can answer `unstable`.** A hive that loads or unloads in each of up to four consecutive walks (microseconds each) makes the listing fail with `unstable`; the caller refuses for that run, never acts on a wrong list. Every caller fails closed with `hku_list_incomplete`.
- **Callers that previously returned partial per-user data from a failed listing now report the failure for that run** (stated in the changelog fragment).
