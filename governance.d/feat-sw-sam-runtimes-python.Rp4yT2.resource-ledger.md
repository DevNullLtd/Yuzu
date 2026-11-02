# Resource Ledger: feat-sw-sam-runtimes-python

Every owning boundary the diff adds or changes in C++ (the runtimes plugin's python legs, `agents/shared/macos_network_mounts.hpp`, the installed-software collector and their unit tests).

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | Windows registry keys in `win::python_rows` (PythonCore root per view, each tag key, each `InstallPath` key) | function-local `Guard` (non-copyable: deleted copy constructor; copy assignment deleted by its reference member) | `ops.open` returns `ERROR_SUCCESS` | `ops.close` in `~Guard`, scope exit | none | RAII on every path, including `continue`/`break` out of the enumeration loop; the FakeOps suite asserts `opened == closed` |
| R2 | `statfs` table from `getmntinfo_r_np(MNT_NOWAIT)` in `yuzu::shared::read_macos_network_mounts` | `std::unique_ptr<struct statfs, decltype(&::free)>` | the call returns | `free` at scope exit | none; the network mount-on paths are copied into a `std::vector<std::string>` | owned before the `n <= 0` check, so a failed read frees too. MOVED from `remote_access_audit_macos.cpp`, now shared by `remote_access_audit` and `runtimes` |
| R3 | Directory descriptors of the Linux and macOS python walks | `DirHandle` (RAII `DIR*`) and `yuzu::agent::ScopedFd` | each hop-by-hop `O_NOFOLLOW` open | scope exit | moved between `PathWalk`/`Opened` holders only | RAII; a failed open closes its descriptor before returning the token |
| R4 | macOS `Resources/Info.plist` read | `read_file_bounded_at` result string | one bounded read | scope exit | none | refused above `kMaxPlistBytes` (256 KiB) |
| R5 | Walk bounds | `WalkBudget` (one per action across all roots: `kMaxRowBytes` 1 MiB of row text, row and entry caps) on Linux/macOS; on Windows `kMaxTagsVisited` 512 across both views, `RowByteBudget{kMaxTagsVisited, kMaxRowBytes}`, `kMaxValueBytes` 64 KiB per value | value types | per dispatch | scope exit | none | exhaustion records `row_cap` and stops; an over-long tag name counts against the 512 cap |

Collector changes with no resource of their own: the escape-aware `split_tokens` (`\|` is field text; the hunk is copied verbatim from the middleware branch so both merge to identical text) and `ConstrainedPolicy::drop_source` with `AdaptedRows::Status::withheld` (copied verbatim from the same branch), used by the `runtimes.python` table row: a constrained python read contributes no rows and the cycle continues.

No thread, socket, subprocess, file write, persistent state or callback is added.
