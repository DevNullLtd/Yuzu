# Build guide

The detail behind CLAUDE.md's `## Build`, `## Test` and `## vcpkg` sections. CLAUDE.md keeps only
the load-bearing rules; this document is the reference.

Related: `docs/windows-build.md` (the Windows path inventory and its two hard rules),
`docs/ci-architecture.md` (the CI matrix), `scripts/setup.sh` (the script itself, whose header
comment carries the same usage block).

## Build

Meson is the sole build system. **Every time you add, remove, or rename a source file, update `meson.build` in the affected directory** and verify the build compiles.

### Prerequisites
- Meson 1.12.0 (the pin in `requirements-ci.txt`, used by the Linux CI legs; the Windows runner
  contract `deploy/windows/toolchain-contract.json` pins 1.11.1; the build's hard floor is
  `meson_version: '>=1.3.0'`), Ninja
- CMake (required by Meson's cmake dependency method — not used as a build system)
- C++23 compiler: GCC 13+, Clang 18+, MSVC 19.38+, or Apple Clang 15+
- vcpkg (set `VCPKG_ROOT`)
- For vcpkg's libpq port (Postgres substrate, ADR-0006; builds postgresql from source): **Linux** needs `bison flex` (apt); **macOS** needs `autoconf automake libtool` (brew); **Windows** none extra (vcpkg auto-acquires winflexbison)

### Quick start (setup script)
```bash
./scripts/setup.sh                              # debug build, default compiler
./scripts/setup.sh --buildtype release --lto    # release + LTO
./scripts/setup.sh --tests                      # enable tests
```
(`--native-file meson/native/*.ini` / `--cross-file meson/cross/*.ini` select compilers / cross targets.)
The script runs `vcpkg install` then `meson setup` automatically.

### Manual configure
```bash
vcpkg install --triplet x64-linux --x-manifest-root=.
meson setup build-linux --buildtype=debug -Dbuild_tests=true \
  -Dcmake_prefix_path=$PWD/vcpkg_installed/x64-linux \
  -Dpkg_config_path=$PWD/vcpkg_installed/x64-linux/lib/pkgconfig,/usr/lib/x86_64-linux-gnu/pkgconfig
meson compile -C build-linux
```
**Both paths are load-bearing, and both point INTO THE TREE.** `--x-manifest-root=.` is vcpkg
*manifest* mode, which installs to `<repo>/vcpkg_installed/<triplet>` — **not** to
`$VCPKG_ROOT/installed/<triplet>`, which stays near-empty (measured: 7 packages vs 237) and
makes `meson setup` fail on `Dependency PostgreSQL not found`. `pkg_config_path` is separately
required because spdlog/fmt resolve via pkg-config, not cmake: with the prefix alone the
headers are found and the link then fails on `undefined reference to fmt::v12::…`. An
out-of-tree build dir (a review worktree, a scratch checkout) needs the same two flags
pointing at a populated `vcpkg_installed`.

### Build options
`-Dbuild_agent` / `-Dbuild_server` / `-Dbuild_examples` (default true — gates only the four demo plugins: `example`, `chargen`, `procfetch`, `netprobe`; every other plugin builds under `-Dbuild_agent` regardless) / `-Dbuild_tests` (default false), and the Meson built-ins `-Db_lto`, `-Db_sanitize=address,undefined` (ASan+UBSan) or `-Db_sanitize=thread` (TSan).

### Per-OS build directory convention

Per-OS build dirs prevent clobbering when one tree is built from multiple hosts (WSL2 + native Windows + macOS): `build-linux` / `build-windows` / `build-macos`. Use `scripts/setup.sh` (auto-picks) or `-C build-<os>`. If setup.sh finds a dir recorded for another host it refuses to reconfigure unless `--wipe` (prevents opaque ninja "dyndep is not an input"/Windows-path failures from reusing a Windows builddir under WSL2); it never auto-wipes, defaults to `--reconfigure`.

### Windows build

`docs/windows-build.md` is the source of truth — MSYS2 bash sequence, the `setup_msvc_env.sh` + `scripts/ensure-erlang.sh` activation pair, path inventory, and two hard rules: **never `vcvars64.bat`** (extension exit-1 corrupts wrappers), **never Clang from `C:\Program Files\LLVM\bin`** (must be cl.exe/MSVC). `cross-platform` + `build-ci` load this on any Windows-touching change.

**Provisioning a native Windows CI runner** — see `deploy/windows/README.md` (provisioning spec, `toolchain-manifest.json`, runner self-test; gateway toolchain via `YUZU_ESCRIPT`/`YUZU_REBAR3`; the 4 runners share one vcpkg cache via `RUNNER_TOOL_CACHE`).

### Cross-compilation
`./scripts/setup.sh --cross-file meson/cross/aarch64-linux-gnu.ini`

## Test

Every test target carries a `suite:` label (`agent`, `tar`, `server`) so `--suite <name>` filters directly:

```bash
meson test -C build-linux --suite <server|agent|tar> --print-errorlogs   # omit --suite for everything
```

Tests require `-Dbuild_tests=true`. vcpkg installs Catch2 only on `x64 | arm64`; the ARM64 cross-compile CI job intentionally skips tests.

### Direct binary invocation

For Catch2 tag filtering (`[rest][token]`, etc.) or raw output, call the test binary directly via the stable per-component symlinks maintained by `scripts/link-tests.sh`:

```bash
tests-build-server-linux_x64/yuzu_server_tests "[rest][token]"
tests-build-agent-linux_x64/yuzu_agent_tests "[metrics]"
```

`scripts/setup.sh` creates the symlinks; on a plain `meson setup` checkout run `bash scripts/link-tests.sh` once after the first `meson compile`. Triplet suffix derives from the host (`linux_x64`, `linux_arm64`, `macos_arm64`, `windows_x64`). Symlinks point at the real build output, so they stay live across rebuilds. `tests-build-*/` is gitignored.

### Third-party warning suppression

Every `dependency()` is marked `include_type: 'system'` so vcpkg/gRPC/abseil/protobuf/Catch2 warnings are `-isystem`-silenced while our code stays `warning_level=3`. **Do not remove `include_type: 'system'`** on new dependencies — load-bearing for build-log readability.

## vcpkg

- Manifest `vcpkg.json`; pinned baseline `4b77da7fed37817f124936239197833469f1b9a8` (matches `vcpkgGitCommitId` in CI). `builtin-baseline` is required by the abseil `version>=` constraint — without it vcpkg resolves against HEAD.
- OpenSSL is **required on every platform including Windows** — gRPC's TLS/JWT/PEM paths compile against OpenSSL headers regardless of linkage, so `grpc.lib` needs `libssl`+`libcrypto`; it is an unconditional top-level dep (the old `!windows`/schannel filter was disproven, #375).
- `catch2` is platform-filtered to `x64 | arm64` (not 32-bit ARM).
- **libpq (ADR-0006/0008):** on Windows it is a **DLL** (the static override covers only the grpc stack), shipped via the release zip's vcpkg-DLL sweep; `libpq_dep` is gated on `build_server` (agent stays SQLite); manifest pins `default-features: false, features: [openssl]`; the buildtype-conditional `_vcpkg_lib_win` pick is load-bearing (pure-C libpq has no `detect_mismatch`, so a wrong-CRT lib links silently). No cmake target carries static libpq's full closure (`libpgcommon`/`libpgport` live in `libpq.pc`'s `Libs.private`) — `meson.build`'s `libpq_dep` block wires it explicitly.
- **Windows grpc/protobuf/abseil is load-bearing — both halves.** The `triplets/x64-windows.cmake` static-linkage override AND meson's hand-wired `protobuf_dep`/`grpcpp_dep` (`cxx.find_library()`) are the only config that avoids both LNK2038 and LNK2005 — don't simplify either half without reading `.claude/agents/build-ci.md` (full #375 timeline + #376 QUIC escape). Linux/macOS unaffected.
- **Linux sanitizer triplets (`x64-linux-asan`/`x64-linux-tsan`) are STATIC (#4019), matching the stock `x64-linux` triplet.** Dynamic linkage (the setting from each triplet's introduction through #4019) split grpc/protobuf/re2 into separate `.so` images in the sanitizer test binaries, each independently embedding abseil's `MixingHashState::kSeed` (self-referential, so copies legitimately diverge) — a `protobuf::Map` populated via one image's hash and queried via another's silently missed an existing key, corrupting Guardian spark-validation lookups nondeterministically under both ASan and TSan. Don't revert to dynamic linkage without reading the triplet files' own header comments — the `-fsanitize=...` flag propagation both triplets exist for works identically under static linkage. This is CI/test-tooling only; no shipped artifact is built from these triplets.
- **TSan on vendored libpq**: `pqSaveParameterStatus` (`fe-exec.c`) races two connections' initial `ParameterStatus` writes into two process-wide statics; suppressed via a compiled-in `__tsan_default_suppressions` hook in `tests/unit/test_runner_main.cpp`, kept honest by the `tests/test_no_connless_pq_escape.py` tripwire (#1611).

## Instruction Engine build-time dependency

The content plane: YAML-defined `InstructionDefinition` → `InstructionSet` → `ProductPack`, executed via `CommandRequest`; `yaml_source` authoritative, denormalized columns for queries. Architecture: `docs/Instruction-Engine.md`; DSL: `docs/yaml-dsl-spec.md`; tutorial: `docs/getting-started.md`.

**Build-time gotcha:** PyYAML is a **hard build dependency** (`meson setup` fails without it). Shipped content is build-time embedded (`embed_content.py` → `bundled_content.cpp`, reseeded into the Postgres `instruction_store` schema on every boot, ADR-0058); the runtime never reads YAML from disk (no `--content-dir` flag). See `docs/Instruction-Engine.md`.
