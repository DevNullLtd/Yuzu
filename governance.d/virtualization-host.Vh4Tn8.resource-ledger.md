# Resource Ledger — virtualization host

Range: `origin/dev..HEAD` (branch `feat/virtualization-host`)

## Summary

This diff introduces **no thread, subprocess, socket, `FILE*`, `sqlite3*`, OpenSSL object, BCrypt
handle, mapped library or temp path**. The only OS handles are opened and closed inside the shared
bounded reader `yuzu::shared::read_file` (`posix_secure_read.hpp`), which owns each descriptor for
the duration of the call and returns the bytes by value. Every object the plugin owns is a value
type under RAII.

## Table 1 — new owned state (all RAII value types)

| Resource | Type | Owner | Scope | Notes |
|---|---|---|---|---|
| `FileRead::data` | `std::string` | `read_source` (Linux leg) | function-local | Bytes of one sysfs, procfs or DMI attribute, capped at 4 KiB (DMI, `/sys/hypervisor/type`, `/run/systemd/container`) or 64 KiB (`/proc/self/cgroup`); a larger file is `oversized`, never a partial read. The descriptor behind it is opened and closed inside `read_open_fd` (`FdCloser`). |
| `Facts` | struct of `std::string` / `std::vector<std::string>` / `std::optional` | `run_linux`, `run_macos`, `run_windows` | function-local | The plain-data input to `decide`; moved into the `Posture` and rendered to rows; nothing escapes the frame. |
| `RsmbRead::bytes` | `std::vector<std::uint8_t>` | `read_smbios` (Windows leg) | function-local | The RawSMBIOSData buffer from `GetSystemFirmwareTable`, capped at 1 MiB by `read_rsmb_table`; decoded by `parse_rsmb` into value types and dropped at the end of `read_smbios`. No handle. |
| `buf` | `std::string` | `sysctl_string` (macOS leg) | function-local | Sized by the two-call `sysctlbyname` probe; no handle. |
| `Posture` | struct of `std::string` / `std::vector<std::string>` | `decide`, `report_host` | function-local | Rows are written through `ctx.write_output` by value. |

## Table 2 — pre-existing resources this diff touches without changing ownership

| Resource | Owner | This diff's interaction |
|---|---|---|
| plugin `execute()` | `VirtualizationPlugin` | One `try { ... } catch (...) { ... }` in `execute_host` wraps the whole body; the catch writes a fixed-token status row inside its own nested `try`/`catch (...)`, so it cannot throw. No new acquisition. |
| CPUID | CPU | `__cpuid_count` / `__cpuidex` are register reads with no resource to release. |

## Tests

Test code adds only Catch2 locals (`std::vector`, `std::string`, `std::optional`). The
local-dispatcher test loads the built plugin through `PluginHandle` (an existing RAII owner); the
OOM-containment case reuses the file's allocator stub.
