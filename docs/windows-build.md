# Windows Build Reference

Reference for the Windows build toolchain paths and prerequisites. CLAUDE.md keeps only the load-bearing rule ("MSYS2 bash + `setup_msvc_env.sh`, NOT `vcvars64.bat`"); this document is the path inventory that `setup_msvc_env.sh` manages for you.

## Build from MSYS2 bash

```bash
source ./setup_msvc_env.sh           # MSVC paths
source scripts/ensure-erlang.sh      # Erlang/OTP on PATH (gateway target)
meson compile -C build-windows       # canonical Windows dir; coexists with build-linux from WSL2
```

**Do NOT use `vcvars64.bat`.** It returns exit code 1 due to optional extension failures (Clang, bundled CMake, ConnectionManager) even though cl.exe is set up correctly. This causes `.bat` wrapper scripts to abort or misbehave. `setup_msvc_env.sh` sets all MSVC paths directly in MSYS2 bash and is the only supported build method.

`scripts/ensure-erlang.sh` is the sibling helper for the Erlang/OTP toolchain (see "Toolchain activation (Erlang on PATH)" in `docs/erlang-gateway-build.md`). Source both before invoking meson if your build touches the gateway custom_target.

## Toolchain paths

All paths are configured by `setup_msvc_env.sh`. Do **not** use Clang (`C:\Program Files\LLVM\bin`) — must use cl.exe / MSVC.

| Tool | Path |
|---|---|
| cl.exe | `C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe` |
| Windows SDK | `C:\Program Files (x86)\Windows Kits\10` (`10.0.26100.0`) |
| cmake.exe | `C:\Program Files\CMake\bin\cmake.exe` (needed by Meson's cmake dep method) |
| ninja.exe | Installed with CMake or VS BuildTools |
| python | `C:\Python314\python.exe` (system-wide, installed via Chocolatey) |
| meson | `C:\Python314\Scripts\meson.exe` (`pip install meson==1.11.1` — the Windows runner contract pin in `deploy/windows/toolchain-contract.json`; Linux CI uses 1.12.0) |
| vcpkg | `C:\vcpkg` (`VCPKG_ROOT`) |
| protoc | `C:\vcpkg\installed\x64-windows\tools\protobuf\protoc.exe` |
| grpc_cpp_plugin | `C:\vcpkg\installed\x64-windows\tools\grpc\grpc_cpp_plugin.exe` |

### Windows SDK pin

Yuzu pins the `10.0.26100.0` SDK target directory and the
`Windows11SDK.26100` component family. This is not an artifact hash: Microsoft
may service that component's bytes while retaining the `.0` target directory.
The target pin is repeated at each boundary that constructs an MSVC
environment:

- `setup_msvc_env.sh` for native MSYS2 sessions;
- every `ilammy/msvc-dev-cmd` workflow step via `with.sdk`;
- `deploy/windows/Provision-Windows-Runner.ps1`, which requests Visual Studio
  component `Microsoft.VisualStudio.Component.Windows11SDK.26100`, verifies
  `Windows.h`, `kernel32.lib`, and `rc.exe`, and records all three artifacts
  plus the version in the host's `toolchain-manifest.json`.

When the reviewed artifacts are already installed on an existing host, refresh
its manifest with `deploy/windows/Update-ToolchainManifest.ps1`. The updater is
the non-provisioning path for heterogeneous runner topology: it refuses live
worker/job processes, preserves the prior runner/PostgreSQL/telemetry inventory,
asserts the candidate against the live host, and atomically keeps a backup.
Do not run Wee Tam's full four-runner provisioner on single-runner Shulgi merely
to emit a manifest.

The target directory and component family are a reviewed repository contract,
not versions chosen during host maintenance. Moving either requires a PR that
updates every boundary together and passes
`tests/test_windows_sdk_contract.py`. Acceptance of a serviced component
payload remains a recorded host-maintenance decision until an immutable
artifact/hash contract is available.

That decision belongs in the approved maintenance/change record, joined to the
reviewed PR and exact commit. For each host, retain the operator/window approval,
provisioning transcript, manifest hash, toolchain assertion result, native
validation run ID, reboot/rollback outcome, and stable installer/artifact hashes
where upstream supplies them. The detailed checklist is in
`deploy/windows/README.md`; package-manager inventory alone is not approval or
payload evidence.

Contract recognition is package-manager-agnostic. A tool installed by
Chocolatey, WinGet, or a reviewed direct installer is acceptable only when the
effective command/path and live artifact probes satisfy the repository
contract; package-manager inventory is not proof of the installed bytes or the
command that CI will execute. Prefer an immutable artifact hash in the reviewed
contract wherever the upstream distribution exposes a stable one.

Dependabot's `github-actions` ecosystem tracks the SHA-pinned
`ilammy/msvc-dev-cmd` action. It cannot update an arbitrary action input such as
`with.sdk`; the repository-contract test makes SDK drift loud instead.

Rollback is also a host migration. Keep runner admission closed, revert the
repository contract, and prove the prior target's `Windows.h`, `kernel32.lib`,
and `rc.exe` exist. Restore a known-good image or reinstall that reviewed SDK
target if necessary, rerun provisioning to regenerate the host manifest,
validate the native MSYS2 build, and only then re-enable runners. A Git revert
does not restore SDK artifacts removed from a host.

## PowerShell: pwsh.exe only

All Yuzu-authored PowerShell scripts and workflow steps require
**PowerShell 7+** (`pwsh.exe`, installed at
`C:\Program Files\PowerShell\7\pwsh.exe`). Stock Windows PowerShell 5.1
(`powershell.exe`) is not supported.

Reason: the repo saves `.ps1` files as UTF-8 without a BOM (POSIX / git
convention). Windows PowerShell 5.1 reads `.ps1` files without a BOM as
the **system ANSI codepage** (Windows-1252 on English installs), which
mangles any non-ASCII character — box-drawing glyphs, em-dashes, etc. —
and can trip the parser in non-obvious ways (a right-double-quote byte
at 0x94 closes a string literal early; downstream tokens become
"command not found" errors). PS 7+ defaults to UTF-8, reading the
files correctly.

Every shipped `.ps1` begins with a `PSVersionTable.PSVersion.Major -lt 7`
guard that exits 1 with an actionable message. CI workflow steps use
`shell: pwsh` rather than `shell: powershell`. The
`yuzu-local-windows` runner has `pwsh` 7.6.1 pre-installed. See
issue #517 for the migration history.

## Running server tests locally (libpq.dll on PATH)

Since #1320 PR 1 the server library links libpq, which is a **DLL** on
Windows (the static triplet override covers the grpc stack only — see the
`libpq_dep` block in the root `meson.build` and the ADR-0008 Correction).
CI's test step prepends `vcpkg_installed/x64-windows/debug/bin` (debug) or
`/bin` (release) to PATH before `meson test`; a developer shell must do
the same or `yuzu_server_tests.exe` / `yuzu-server.exe` aborts at load
with a libpq.dll-not-found error:

```bash
export PATH="$PWD/vcpkg_installed/x64-windows/debug/bin:$PATH"   # MSYS2 bash
meson test -C build-windows --suite server --print-errorlogs
```

The release zip is unaffected — its vcpkg-DLL sweep bundles `libpq.dll`
next to the binaries, same as `sqlite3.dll` and the OpenSSL DLLs.
