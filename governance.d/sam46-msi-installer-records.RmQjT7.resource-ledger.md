# Resource Ledger — msi_packages installer_records (SAM-46 part 2)

Range: `0c68ac5043833decce953e5cb3f45d173374d7d1..5743f8672d` (branch `feat/sam-46-msi-installer-records`)

## Summary

This diff introduces one detached worker thread, one process-wide single-flight slot, a held no-reparse file handle per package read and three Windows Installer handle kinds, plus registry key handles. Every handle is owned by an RAII type. The single caller-side manual release is `slot.release()` on the `Rejected` arm of `read_property_table`, where the worker never ran and so cannot release; it is the only release on that path (independently proven by the cpp-safety review). No temp path, subprocess, `FILE*`, `sqlite3*`, OpenSSL object, BCrypt handle or mapped library is introduced.

## Table 1 — new owned state

| Resource | Type | Owner | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| Registry keys (Products root, per-product `InstallProperties`, UpgradeCodes root and subkey, ProfileList) | `HKEY` in `yuzu::win::RegKey` | the enumerating function / lambda | `RegOpenKeyExW` into `RegKey::put()` | `RegKey` destructor | none | scope exit on every return, including the early `return false` inside the walk lambda |
| Cached-package file handle | `yuzu::win::NoReparseHandle` in `OpenedPackage::hold` | `fill_package`'s local `opened` | `open_package`, after status ok and the attribute check | `OpenedPackage` destructor, after the database read, on the dispatching thread, whatever the read status; at most one held at a time, at most 5 s each | moved from `opened.file` to `out.hold` only after the checks | early returns leave the handle to `opened.file`'s own destructor |
| `MSIHANDLE` database, view, per-row record | `MsiHandle` (RAII, non-copyable, TU-local in `msi_database_read.cpp`) | `read_worker` on the worker thread | `MsiOpenDatabaseW`, `MsiDatabaseOpenViewW`, `MsiViewFetch` via `put()` | `MsiHandle` destructor (`MsiCloseHandle`), on the worker's own thread, destruction order rec, view, db | never leaves the worker; the caller never receives a handle | scope exit; the record is declared per loop iteration |
| Detached worker thread | `yuzu::shared::bounded_call_ex` (existing primitive, 64-call ceiling guard) | agent-core (never unloaded) | `read_property_table`, after `SingleFlightSlot::try_acquire` on the dispatching thread | the thread ends when `read_worker` returns | none | `TimedOut`: abandoned, keeps the slot until it returns; `Rejected` (ceiling, `make_shared` or thread constructor throw): `fn` never ran |
| Process-wide `SingleFlightSlot g_slot` | `std::atomic<bool>`, static in agent-core | agent-core | `try_acquire` on the dispatching thread | `SlotRelease` RAII on the worker (constructed first, destroyed last), or one `slot.release()` by the caller on `Rejected` | none | the worker closure (which copies the path and can throw) is built BEFORE `try_acquire` |
| Worker closure state | `std::string` path copy, `SlotRelease` | the worker lambda | before the slot is taken | worker end | moved into `bounded_call_ex` | n/a |
| Registry and read buffers | `std::wstring`, `std::vector<wchar_t>`, `std::vector<std::string>` | function locals | per call | scope exit | none | RAII |
| Plugin shutdown quiesce | `MsiPackagesPlugin::shutdown` (noexcept) | the plugin | polls `read_in_flight()` every 20 ms for at most `2 * kPackageDeadline` | n/a | n/a | bounded, never joins; a second production `sleep_for` poll exists in `windows_optional_features_plugin.cpp` (the Gate 1 claim that this was the only one was wrong) |

## Table 2 — pre-existing resources this diff touches without changing ownership

| Resource | Owner | Interaction |
|---|---|---|
| `open_file_no_reparse` volume-root and file handles | `NoReparseHandle` | a defaulted `share_access` parameter was added; the default mask is unchanged |
| `MsiPackagesPlugin::execute` try/catch envelope | the plugin | one new action branch inside it |
| `list_inventory` collect() | the plugin | a third injected callable (registry map lookup); no new handle |

## Tests

Catch2 locals only. The Windows-only cases use `TempDir{"yuzu_test_msi_read_"}`, function-local `static SingleFlightSlot` objects (a worker the slot was handed to never outlives it) and a held `NoReparseHandle`; no process is spawned.
