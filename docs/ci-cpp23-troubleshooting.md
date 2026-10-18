# Troubleshooting CI for Cross-Platform C++23 Projects

**A practical guide to getting C++23 code compiling on GitHub Actions across GCC, Clang, MSVC, and Apple Clang — the problems nobody warns you about.**

This was written after spending a full day debugging CI failures for [Yuzu](https://github.com/Tr3kkR/Yuzu), a cross-platform C++23 endpoint management platform. Every issue below was discovered the hard way.

> **Supported compilers today (#5929):** GCC 15+, Clang 21+, MSVC 19.44+ (VS 2022 17.14) and Apple Clang 21+ — exactly the set CI builds and tests; see "Compiler floor" in `docs/build-guide.md`. The sections below were written when CI ran GCC 13, Clang 18/19 and Apple Clang 15/16 on `ubuntu-24.04` and `macos-14`. Those compilers are now below the floor and the matrix at the end of this page is a historical record of them, not a support statement. The lessons (libstdc++ selection by Clang, Meson flag translation, `ld64` flags, ccache with native files) still apply.

---

## 1. Clang 18 + GitHub Actions = broken `std::expected`

**Symptom:** `error: no template named 'expected' in namespace 'std'` with clang-18, `-std=c++23`, on `ubuntu-24.04` runners.

**Root cause chain:**

1. The `ubuntu-24.04` runner has GCC 12, 13, AND 14 pre-installed
2. Clang doesn't ship its own C++ standard library on Linux — it uses GCC's libstdc++
3. Clang's `GCCInstallationDetector` always picks the **highest version** → GCC 14
4. libstdc++'s `<expected>` header is guarded by `__cpp_concepts >= 202002L`
5. **Clang 18 sets `__cpp_concepts` to a value below `202002L`**
6. So `<expected>` compiles to an empty header — the template is never defined

**Why it works locally but fails on CI:** A fresh `ubuntu:24.04` Docker container only has GCC 13. Clang picks it and everything works. The CI runner has three GCC versions and clang picks the wrong one.

**Fix:** Upgrade to **Clang 19**, which correctly sets `__cpp_concepts = 202002L`. This was explicitly noted in the [Clang 19.1.0 release notes](https://releases.llvm.org/19.1.0/tools/clang/docs/ReleaseNotes.html).

```yaml
# ci.yml — use clang-19, not clang-18
matrix:
  compiler: [gcc-13, clang-19]

# Install step
sudo apt-get install -y clang-19
```

**Alternative fixes (if you must stay on clang-18):**

```bash
# Force clang to use GCC 13's headers
clang++-18 --gcc-install-dir=/usr/lib/gcc/x86_64-linux-gnu/13

# Or purge GCC 14 (fragile — runner images change)
sudo apt-get purge -yq gcc-14 g++-14 libstdc++-14-dev

# Or use clang's own libc++ (changes ABI — all deps must match)
sudo apt-get install -y libc++-18-dev libc++abi-18-dev
clang++-18 -stdlib=libc++ -std=c++23
```

**References:**
- [actions/runner-images#8659](https://github.com/actions/runner-images/issues/8659)
- [actions/runner-images#11229](https://github.com/actions/runner-images/issues/11229)
- [clangd/clangd#2200](https://github.com/clangd/clangd/issues/2200)

---

## 2. Apple Clang: version numbers lie

Apple Clang version numbers **do not match upstream LLVM**. "Apple clang version 15.0.0" is based on LLVM 16, not LLVM 15.

| Xcode | Apple Clang | Actual LLVM basis | GitHub runner |
|-------|------------|-------------------|---------------|
| 15.4 | 15.0.0 | ~LLVM 16 | `macos-14` |
| 16.0 | 16.0.0 | ~LLVM 17 | `macos-15` |

**Practical impact on C++23:**

| Feature | macos-14 (Xcode 15) | macos-15 (Xcode 16) |
|---------|---------------------|---------------------|
| `std::expected` | Yes | Yes |
| `std::format` | Needs `-mmacosx-version-min=13.3` | Needs `-mmacosx-version-min=13.3` |
| `std::chrono::clock_cast` | **No** | **No** |
| CTAD for aggregates | No | Yes |
| Deducing `this` | No | Yes |
| `-std=c++23` flag | **No** (needs `-std=c++2b`) | Yes |

**Fix:** Use `macos-15` runners and set the deployment target.

```yaml
# ci.yml
runs-on: macos-15

# meson native file
[built-in options]
cpp_std = 'c++23'
cpp_args = ['-mmacosx-version-min=13.3']
cpp_link_args = ['-mmacosx-version-min=13.3']
```

### The deployment target trap

Apple gates certain C++23 library features behind **minimum macOS version** because the implementation lives in the system `libc++.dylib`. If you compile with default settings but use `std::format`, you get link-time errors or runtime crashes on older macOS. The threshold is **macOS 13.3** for `std::format`, `std::to_chars(float)`, and `std::from_chars(float)`.

### `std::chrono::clock_cast` — broken everywhere

`clock_cast` is not implemented in Apple's libc++ on any version, and it's incomplete in upstream libc++ too. Use a portable alternative:

```cpp
// Instead of: auto sys_tp = std::chrono::clock_cast<std::chrono::system_clock>(file_tp);
// Use relative offset (accurate to nanoseconds, portable everywhere):
auto file_now = fs::file_time_type::clock::now();
auto sys_now  = std::chrono::system_clock::now();
auto sys_tp   = sys_now + (file_tp - file_now);
```

### Don't use raw `-std=c++23`

Apple Clang 15 doesn't accept `-std=c++23` — it needs `-std=c++2b`. If your build system uses raw compiler flags, it will break on macOS.

**Fix:** Let your build system handle the translation. In Meson, set `cpp_std = 'c++23'` as a project option, not as a raw argument. Meson emits the correct flag per compiler.

```meson
# Good — Meson translates per compiler
project('myproject', 'cpp', default_options: ['cpp_std=c++23'])

# Bad — breaks Apple Clang 15
add_project_arguments('-std=c++23', language: 'cpp')
```

---

## 3. macOS linker rejects GNU flags

**Symptom:** `ld: unknown option: -z` on macOS.

Apple's `ld64` linker does not support GNU ld flags like `-Wl,-z,relro,-z,now` (RELRO + immediate binding). These are ELF security hardening flags that don't apply to Mach-O binaries.

```meson
# Guard for ELF platforms only
if host_machine.system() != 'darwin'
  add_project_link_arguments('-Wl,-z,relro,-z,now', language: 'cpp')
endif
```

---

## 4. macOS-specific API differences

These are **platform differences**, not compiler version issues. They apply regardless of which Xcode you use.

- **`execvpe`** — Linux-only. Use `execvp` on macOS/BSD.
- **`extern char **environ`** — not available in anonymous namespaces on macOS. Use `_NSGetEnviron()` from `<crt_externs.h>`.
- **Path comparisons** — macOS `/var` is a symlink to `/private/var`. Always `fs::canonical()` both sides before comparing.

---

## 5. vcpkg on CI: the 90-minute tax

Without binary caching, vcpkg builds gRPC + protobuf + abseil from source on every CI run. This takes 40-90 minutes.

**Fix:** Enable GitHub Actions binary caching.

```yaml
env:
  VCPKG_BINARY_SOURCES: "clear;x-gha,readwrite"

steps:
  # This step exports the cache URL — required for x-gha backend
  - uses: actions/github-script@v7
    with:
      script: |
        core.exportVariable('ACTIONS_CACHE_URL', process.env.ACTIONS_CACHE_URL || '');
        core.exportVariable('ACTIONS_RUNTIME_TOKEN', process.env.ACTIONS_RUNTIME_TOKEN || '');
```

First run: still slow (populating cache). Every subsequent run: ~2-5 minutes.

### Don't use `-release` triplets

vcpkg's release-only triplets (`x64-linux-release`, `arm64-osx-release`) can produce broken CMake config files where version strings are empty. Stick to standard triplets (`x64-linux`, `arm64-osx`).

---

## 6. ccache: silently doing nothing

If you use Meson native files with a `[binaries]` section, Meson ignores `CC`/`CXX` environment variables — so your `CC='ccache gcc-13'` never reaches the compiler. ccache is installed, configured, and cached, but never invoked.

```ini
# Bad — overrides CC/CXX env vars, bypasses ccache
[binaries]
c   = 'gcc-13'
cpp = 'g++-13'

[built-in options]
cpp_std = 'c++23'
```

```ini
# Good — let CC/CXX from the environment control the compiler
[built-in options]
cpp_std = 'c++23'
```

For **cross-compilation** files, `[binaries]` is required (Meson doesn't read env vars for cross builds). Use array syntax to include ccache:

```ini
[binaries]
c   = ['ccache', 'aarch64-linux-gnu-gcc']
cpp = ['ccache', 'aarch64-linux-gnu-g++']
```

Also, don't use `github.sha` in your ccache key — it guarantees a miss every run:

```yaml
# Bad — misses every time
key: ccache-${{ github.sha }}

# Good — hits when source hasn't changed
key: ccache-${{ matrix.compiler }}-${{ hashFiles('**/*.cpp', '**/*.hpp', '**/*.h') }}
```

---

## 7. CI workflow hygiene

Things we added after getting burned:

```yaml
# Manual re-runs without pushing
on:
  workflow_dispatch:

# Least privilege
permissions:
  contents: read

# PR-aware concurrency (prevents dependabot PRs from cancelling each other)
concurrency:
  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: true

# Don't let hung builds burn 6 hours of runner time
timeout-minutes: 90
```

---

## 8. Validate locally with Docker

Don't iterate on CI by pushing and waiting 40 minutes. Build a local CI image with deps pre-compiled:

```dockerfile
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y \
    cmake ninja-build gcc-13 g++-13 clang-19 ccache pkg-config \
    curl zip unzip tar python3-pip git
RUN pip3 install meson==1.9.2

# Pre-build vcpkg deps (the expensive part)
COPY vcpkg.json vcpkg-configuration.json ./
RUN vcpkg install --triplet x64-linux --x-manifest-root=.
```

```bash
# Build once (~40 min), reuse forever
docker build -t my-ci -f Dockerfile.ci .

# Run CI locally (~3 min with ccache)
docker run --rm -v $(pwd):/src my-ci
```

This is how we found most of the issues above — fast iteration in Docker, then translate fixes to GitHub Actions.

---

## Summary: the C++23 CI compatibility matrix (historical, pre-#5929 compilers)

Every compiler in this table is below the current floor. For the floor compilers (GCC 15, Clang 21, MSVC 19.44, Apple Clang 21) see the matrix in `.claude/agents/cpp-expert.md`; the divergences it still records at the floor are Apple libc++'s missing `std::chrono::clock_cast` and MSVC's unverified P2718R0 (range-for temporary lifetime extension) support.

| Feature | GCC 13 | Clang 18 | Clang 19 | MSVC 19.38+ | Apple Clang 15 | Apple Clang 16 |
|---------|--------|----------|----------|-------------|----------------|----------------|
| `std::expected` | Yes | **No*** | Yes | Yes | Yes | Yes |
| `std::format` | Yes | Yes | Yes | Yes | macOS 13.3+ | macOS 13.3+ |
| `std::chrono::clock_cast` | Yes | Yes | Yes | Yes | **No** | **No** |
| CTAD for aggregates | Yes | Yes | Yes | Yes | **No** | Yes |
| `-std=c++23` flag | Yes | Yes | Yes | N/A | **No** (`c++2b`) | Yes |

*\* Clang 18 technically supports `std::expected`, but fails when paired with GCC 14's libstdc++ on GitHub Actions runners due to the `__cpp_concepts` feature test macro.*

---

*Written after a full day of debugging. If this saves you time, that's the point.*
