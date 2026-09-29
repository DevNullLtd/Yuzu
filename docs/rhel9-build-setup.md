# Building Yuzu on RHEL 9 / Rocky 9 / AlmaLinux 9

This is the enterprise-Linux counterpart to the apt recipe in `.github/workflows/ci.yml`. CI
exercises Ubuntu 24.04/26.04, macOS and Windows only — RHEL-family hosts are a supported *developer*
platform, not a CI-covered one, so this doc records a verified sequence rather than an
automatically-regression-tested one. Both verified runs were Rocky 9.8 - the re-verification with
SELinux enforcing (see the verified-run section); the RHEL and Alma branches use the same packages
but have not been exercised, arm64 is unverified, and the container checks run unconfined.

**One command:**

```bash
bash scripts/setup-rhel9.sh --with-postgres          # provision
source ~/.config/yuzu/toolchain-env.sh               # activate (also hooked into ~/.bashrc)
./scripts/setup.sh --tests --native-file meson/native/linux-gcc13.ini
yz_pkgconfig && meson configure build-linux --clearcache -Dpkg_config_path=$PWD/vcpkg_installed/x64-linux/lib/pkgconfig
meson compile -C build-linux
```

The fourth line matters: `scripts/setup.sh` passes only `-Dcmake_prefix_path`, while `CLAUDE.md`'s
manual-configure marks `-Dpkg_config_path` load-bearing too - spdlog/fmt resolve via pkg-config
first, and relying on the cmake fallback to chain fmt is at the mercy of the port version.
`yz_pkgconfig` (defined in the generated env file) puts the checkout's vcpkg `.pc` directory on
`PKG_CONFIG_PATH` for tools run by hand. `--clearcache` is load-bearing, not hygiene: setup.sh's
configure has already resolved and cached spdlog/fmt through cmake, and meson's dependency cache is
consulted before `pkg_config_path`, so without it the pin never takes effect for exactly the
dependencies it exists for. (Aligning `setup.sh` itself so none of this is needed is #3725.)

The script is idempotent — re-running it on a provisioned box changes nothing. (One exception by
design: a box provisioned before a recipe update gets the updated env file - `yz_pkgconfig` and
friends - only on re-run; re-run once and re-source after pulling a newer recipe.) Verify a machine at
any time with `bash scripts/setup-rhel9.sh --check --with-postgres`.

The rest of this doc explains *why* each piece is what it is, because the four things most likely
to bite you (the compiler, the native file, `pg_hba.conf`, and the test role's privileges) all fail
in confusing ways.

---

## The four traps

### 1. The system GCC cannot build this project

RHEL 9's `gcc` is 11. Yuzu is C++23 and the documented floor is **GCC 13+ / Clang 18+**. The fix is
a **Software Collection**: `gcc-toolset-14` ships GCC 14.2.1 *and its own libstdc++ 14 headers*,
which is the part that matters — `<expected>` and the C++23 `<format>` additions live in libstdc++,
and the base system's `libstdc++-devel` is 11.5.

This also rules out the obvious-looking alternative: AppStream carries `clang` 21, but Clang uses
the *system* libstdc++ headers, so a bare `clang++ -std=c++23` still gets the 11.5 library. Using
Clang here means installing `gcc-toolset-14` anyway and pointing Clang at it with
`--gcc-install-dir`. Not worth it unless you specifically want a second-opinion compile.

A Software Collection must be activated **per shell**:

```bash
source /opt/rh/gcc-toolset-14/enable
```

Inside the collection the binaries are plain **`gcc` / `g++`** — *not* `gcc-14` / `g++-14`. That
detail drives trap 2. (gcc-toolset links the newer libstdc++ bits statically, so the binaries you
build still run on the base system without the collection activated.)

### 2. Use `meson/native/linux-gcc13.ini`, whatever your GCC version

The native files are not interchangeable:

| File | Verdict on RHEL 9 |
|---|---|
| `linux-gcc13.ini` | ✅ **Use this.** Contains only `cpp_std = 'c++23'` — no hard-coded binaries, no linker override. Compiler selection comes from `CC`/`CXX`. This is what the GHA-hosted ubuntu-24.04 canary uses. |
| `linux-gcc14.ini` | ❌ Hard-codes `c = 'gcc-14'` / `cpp = 'g++-14'`. Those names do not exist inside the Software Collection — meson fails to find a compiler. |
| `linux-gcc15.ini`, `linux-clang21.ini` | ❌ Both force `-fuse-ld=mold`. `mold` is not in BaseOS/AppStream/CRB (EPEL only) and is not installed by this recipe — every link fails. |

The name "gcc13" describes the CI leg it was written for, not a compiler constraint.

### 3. `postgresql-setup --initdb` leaves host auth on `ident`

Needed only if you want the server suite's `[pg]` tests to actually run. RHEL's initdb writes:

```
host    all             all             127.0.0.1/32            ident
```

`ident` rejects the password auth in `YUZU_TEST_POSTGRES_DSN`, and the failure surfaces as a
connection error deep inside the test run rather than as a config error. Change the two loopback
`all all` lines to `scram-sha-256` and `systemctl reload postgresql`. `setup-rhel9.sh
--with-postgres` does this, keeps the first pre-edit copy as `pg_hba.conf.yuzu-orig` (owner and mode
preserved, never overwritten on later runs), and prints a warning rather than editing silently.

**The recipe assumes a dedicated local cluster.** That edit, the `yuzu` role's password and the
`pg_signal_backend` grant are cluster-wide, so the script performs them only on a cluster it created
itself or one you hand it with `--adopt-cluster`. Consent is recorded in a marker
(`/var/lib/pgsql/.yuzu-provisioned`, outside the data directory) holding the cluster's `pg_control`
system identifier, so it binds to the *cluster*, not the path: a cluster replaced at
`/var/lib/pgsql/data` - a hand re-initdb, a restore - is "any other cluster" again. That includes the
most routine cause: a major-version `postgresql-setup --upgrade` rewrites the cluster under a new
identifier, so re-run with `--adopt-cluster` once afterwards. Any other cluster
- say, one already serving a native Yuzu server under its own `yuzu` role - is verified, never
changed: the script stops and names the statement to run by hand.

Remember the skip-vs-fail contract from `CLAUDE.md`: `YUZU_TEST_POSTGRES_DSN` **unset** → the `[pg]`
tests skip cleanly; **set but broken** → hard FAIL. So a misconfigured cluster is worse than none.

### 4. The test role needs `pg_signal_backend`, not just `CREATEDB`

This one cost a shard timeout to find, and it is the least obvious failure in this document.

`PostgresTestDb` creates an ephemeral `yuzu_test_<epoch>_<salt>_<n>` database per test and drops it
`WITH (FORCE)`. `FORCE` terminates the backends still attached to the database - in practice an
autovacuum worker, which runs under no role at all - and terminating a backend that is not your own
requires membership in the predefined **`pg_signal_backend`** role. A test role with only
`LOGIN CREATEDB` gets:

```
PostgresTestDb: DROP DATABASE failed — leaked yuzu_test_1786828330_843575621_1284:
ERROR:  permission denied to terminate process
```

Nothing fails at that moment. The tests keep passing; every test whose drop races an attached
autovacuum worker leaks its database, the cluster gets slower, the race gets likelier, and the
`server pg unit tests shard B` target blows its meson timeout (`tests/meson.build`; 700 s on current
dev, 600 s at the time of the reference run) and is SIGKILLed — with the actual cause buried in
thousands of lines of per-test `NOTICE:` output. On the reference box this left **70 orphaned
databases** behind.

```sql
GRANT pg_signal_backend TO yuzu;
```

`setup-rhel9.sh --with-postgres` grants it, `--check --with-postgres` verifies both the membership and
that no `yuzu_test_*` databases have leaked. If you are cleaning up after hitting this:

```bash
sudo -u postgres psql -tAc \
  "SELECT datname FROM pg_database WHERE datname LIKE 'yuzu\_test\_%'" |
  while read -r db; do
    [ -n "$db" ] && sudo -u postgres psql -qc "DROP DATABASE IF EXISTS \"$db\" WITH (FORCE)"
  done
```

---

## RHEL vs Rocky vs Alma

The only material divergence is repository enablement. `ninja-build` lives in **CRB**
(CodeReady Builder, formerly PowerTools), which ships disabled on Rocky/Alma and is
subscription-gated on RHEL. (`ccache` is one repo further out - EPEL, not CRB; see below.)

| | Rocky 9 / Alma 9 | RHEL 9 |
|---|---|---|
| CRB | `sudo dnf config-manager --set-enabled crb` | `sudo subscription-manager repos --enable codeready-builder-for-rhel-9-$(uname -m)-rpms` |
| Everything else | identical | identical |

**EPEL is not required to build.** Every *mandatory* package resolves from BaseOS / AppStream / CRB —
verified with `dnf repoquery --installed --qf '%{from_repo}'` on the reference box, which is also how
`docs/rhel9-toolchain-manifest.json` records provenance.

The one wrinkle: **`ccache` is EPEL-only** on this distro family. It is in neither BaseOS, AppStream
nor CRB (`ninja-build` *is* in CRB, which is easy to conflate). ccache is optional — without it the
build works, rebuilds are just slower — so `setup-rhel9.sh` installs it only if it is already
reachable, warns otherwise, and writes an env file whose `CC`/`CXX` adapt:

```bash
export CC="ccache gcc"   # if ccache is on PATH
export CC="gcc"          # otherwise
```

Pass `--with-epel` to have the script enable EPEL and pick ccache up. It is off by default because
enabling EPEL on a managed work machine is a policy decision, not a build requirement. EPEL is also
where `mold` and Erlang live, if you later want either.

---

## What gets installed, and why

```bash
sudo dnf install -y \
  gcc-toolset-14 \
  cmake ninja-build pkgconf-pkg-config make \
  bison flex autoconf automake libtool \
  perl perl-IPC-Cmd perl-FindBin perl-File-Compare perl-Pod-Html \
  systemd-devel glibc-devel kernel-headers libblkid-devel \
  python3-pip zip unzip tar git

sudo dnf install -y ccache          # optional, EPEL only — see above
```

`curl` is deliberately not in that list: stock RHEL-family images ship `curl-minimal`, which already
provides the `curl` binary vcpkg needs, and installing the full `curl` package on top of it is a
package conflict that aborts `dnf`. The script adds `curl` only when no `curl` binary exists at all.

| Package(s) | Why |
|---|---|
| `gcc-toolset-14` | C++23. See trap 1. |
| `cmake` | Not a build system here — Meson's `dependency(..., method: 'cmake')` resolution needs it, which is how gRPC/protobuf/SQLite/PostgreSQL/Catch2 are all found. |
| `ninja-build` | Meson's backend (CRB). |
| `bison`, `flex` | vcpkg's `libpq` port builds PostgreSQL from source and cannot auto-acquire these on Linux. |
| `perl` + `perl-IPC-Cmd`, `perl-FindBin`, `perl-File-Compare`, `perl-Pod-Html` | vcpkg's `openssl` port is a Perl-driven build. A minimal RHEL install has no `perl` at all. |
| `systemd-devel` | `agents/core/meson.build` takes a **required** `libsystemd` dependency (`systemd_guard` defaults to `enabled` in `meson.options`). The RHEL name for CI's `libsystemd-dev`. Opt out with `-Dsystemd_guard=disabled` if you must. |
| `libblkid-devel` | `agents/plugins/bitlocker/meson.build` takes a **required** `blkid` dependency on Linux (in-process libblkid, util-linux). The RHEL name for CI's `libblkid-dev`; not pulled in transitively. |
| `autoconf`, `automake`, `libtool` | Needed by several vcpkg ports (grpc/c-ares, xmlsec, libpq's autoreconf path). |
| `glibc-devel`, `kernel-headers` | RHEL equivalent of CI's `linux-libc-dev`. |
| `ccache` | **Optional, EPEL-only.** `CC`/`CXX` are set to `ccache gcc` / `ccache g++` when present (matching CI), plain `gcc`/`g++` otherwise. |

**Do not install `meson` from dnf** — Rocky/RHEL 9 ship 0.63.3, below the `meson_version: '>=1.3.0'`
floor in `meson.build`. Meson comes from pip - but **not at the CI pin**: `requirements-ci.txt` pins
meson 1.12.0, whose `Requires-Python` is `>=3.10`, and RHEL 9's `python3` is 3.9. The recipe installs
1.11.2, the last meson that installs under 3.9; the build is unaffected (the floor is 1.3.0), and the
script warns at step 3 whenever its pin and CI's differ:

```bash
python3 -m pip install --user meson==1.11.2 pyyaml==6.0.3
```

The system Python 3.9 is fine (meson 1.11.2 declares `requires_python >= 3.7`). PyYAML is a **hard
configure-time dependency** — `server/core/meson.build` runs `python3 -c 'import yaml'` and
hard-errors if it fails, because content embedding (`embed_content.py`) needs it. The rpm
`python3-pyyaml` (5.4.1) would work; the pinned 6.0.3 in `~/.local` shadows it and matches
`requirements-ci.in`.

> Do not install the hash-pinned `requirements-ci.txt` here: its meson pin needs Python 3.10+, so
> under Python 3.9 pip refuses it outright. Install the two packages that matter explicitly.
> (`gcovr` from that file is only for the nightly coverage job.)

### The Python 3.9 ceiling

`meson setup` emits:

```
NOTICE: You are using Python 3.9 which is EOL. Starting with v1.12.0, Meson will require Python 3.10 or newer
```

That day has come: CI moved to meson 1.12.0 on 2026-08-21. This recipe stays on 1.11.2 under the
system interpreter on purpose - the alternative changes which interpreter runs the build scripts and
needs the reference run redone - and `setup-rhel9.sh` warns at step 3 while the two pins differ.
Following the CI pin means a newer interpreter from AppStream (`python3.12` is packaged); that
migration is tracked in #3696. Two things to get right at that point:

1. Install meson under the new interpreter — `python3.12 -m pip install --user meson==<ver>`.
2. **PyYAML must be importable by whatever `python3` *meson* resolves**, which is a separate
   question. `find_program('python3')` picks up `/usr/bin/python3` (3.9) unless you shadow it, and
   that is the interpreter that runs `embed_content.py` and `gen_proto.py`. Installing meson under
   3.12 while leaving PyYAML only under 3.9, or vice versa, produces a confusing configure-time
   failure.

   Simplest resolution: keep PyYAML installed for *both* interpreters, or put `python3.12` first on
   `PATH` as `python3` so meson and the build scripts agree.

**Do not install `libpq-devel`** — libpq comes from vcpkg as a static library, and CI asserts the
built binary has no dynamic libpq (ADR-0008).

---

## vcpkg

```bash
git clone https://github.com/microsoft/vcpkg.git ~/vcpkg
git -C ~/vcpkg checkout "$(python3 -c "import json;print(json.load(open('vcpkg.json'))['builtin-baseline'])")"
~/vcpkg/bootstrap-vcpkg.sh -disableMetrics
export VCPKG_ROOT=~/vcpkg
```

The baseline is read from `vcpkg.json` rather than written out here on purpose. The same SHA also
appears as `default-registry.baseline` in `vcpkg-configuration.json` and `VCPKG_COMMIT` in `ci.yml`,
and `.github/workflows/vcpkg-baseline-update.yml` rewrites every tracked copy when the baseline moves
— a list that `deploy/windows/Test-ToolchainContract.ps1` enforces against a repo-wide `git grep`. A
literal SHA in this file would be an untracked copy that silently goes stale, and would fail that
check. `scripts/setup-rhel9.sh` reads it the same way.

**Activate gcc-toolset before the first `vcpkg install`** so every port is built by GCC 14 rather
than the system GCC 11. Budget for a cold from-source build of all 22 ports (grpc, protobuf, abseil,
openssl, libpq, libxml2, xmlsec, sqlite3, zlib, catch2 …) and roughly 15–25 GB of
`buildtrees`/`packages` churn; see `docs/rhel9-toolchain-manifest.json` for measured timings on the
reference box.

---

## Environment

`setup-rhel9.sh` writes a sourceable `~/.config/yuzu/toolchain-env.sh` and hooks it into `~/.bashrc`
behind a guard block, so it is safe on re-run. (To undo, delete the block between
`# >>> yuzu toolchain >>>` and `# <<< yuzu toolchain <<<` in `~/.bashrc`, then
`rm ~/.config/yuzu/toolchain-env.sh`; the cluster, role and `~/vcpkg` are left to you.)

```bash
source /opt/rh/gcc-toolset-14/enable   # guarded: no stacked PATH entries
PATH="$HOME/.local/bin:$PATH"          # meson
export VCPKG_ROOT="$HOME/vcpkg"
export CC="ccache gcc" CXX="ccache g++"
export YUZU_TEST_POSTGRES_DSN="postgresql://yuzu:yuzu@127.0.0.1:5432/yuzu_test"   # --with-postgres only, once verified
```

The DSN line is written only by a `--with-postgres` run, and only after the cluster has answered on
that exact DSN - the skip-vs-fail contract above means an exported-but-unreachable DSN would turn
every `[pg]` test from a clean skip into a hard failure. The file is regenerated from the flags of
the *most recent* run, so a later run without `--with-postgres` drops the DSN again (the tests then
skip - the safe direction); keep passing the flag. `YUZU_TEST_ENABLE_PG` is a compile-time define in
`tests/meson.build`, not an environment variable, so the file does not export it.

The DSN address/role/database match the native-cluster branch of `scripts/ci/ensure-postgres.sh`, so
that script is a no-op on a box provisioned this way. The `yuzu` role needs **`CREATEDB`** —
`PostgresTestDb` (`tests/unit/test_helpers.hpp`) creates and drops an ephemeral
`yuzu_test_<epoch>_<salt>_<n>` database per test. The script logs in with the DSN's own credentials
before deciding: on a cluster it manages, a `yuzu` role that lacks `LOGIN`, `CREATEDB`, or the `yuzu`
password is repaired with `ALTER ROLE` rather than accepted on its name; on any other cluster it
stops and tells you what to run (see trap 3). The DSN is exported only once the listener on
`127.0.0.1:5432` is proven to be that cluster (same `pg_control` system identifier read locally and
over TCP), not merely something that answers.

---

## Verify

```bash
bash scripts/setup-rhel9.sh --check --with-postgres    # every gate below, scripted
```

Manually:

```bash
g++ --version                      # 14.2.1
meson --version                    # 1.11.2
python3 -c "import yaml; print(yaml.__version__)"
bash scripts/setup-rhel9.sh --check     # includes a <expected> compile probe: proves the toolset's libstdc++ is in play
psql "$YUZU_TEST_POSTGRES_DSN" -tAc 'SELECT 1'
```

After the build:

```bash
bash scripts/link-tests.sh          # see note below
meson test -C build-linux --print-errorlogs
```

> `scripts/setup.sh` calls `link-tests.sh` itself, but it does so at *configure* time — before the
> test binaries exist — so on a fresh checkout that call legitimately links nothing ("skipped N
> not-yet-built"). Run it once by hand after the first `meson compile` to get the stable
> `tests-build-<component>-linux_x64/` symlinks. They point at the real build output, so they stay
> live across later rebuilds.

Confirm the PG-backed tests really ran rather than skipped:

```bash
tests-build-server-linux_x64/yuzu_server_tests "[pg]"
```

---

## Verified reference run

**Re-verified 2026-08-31 (script as of `5bc96ea73`)** in a Rocky 9.8 KVM guest (12 vCPU /
23 GB) with SELinux **enforcing** and real systemd - the `postgresql-setup --initdb` + `systemctl`
path ran genuinely, not shimmed. The recipe (`--with-postgres --manifest`) completed with zero
failed steps, `--check --with-postgres` passed every check, and the full
`setup.sh --tests` → `meson compile` → `meson test` sequence gave 35 OK / 2 skipped / 2 failed -
the same two pre-existing failures as the original run below (the SQLite `RETURNING` telemetry
limitation, and the known Linux-only MCP case, #2610 family). All 11 `[pg]` shards passed against
the recipe-provisioned cluster. `docs/rhel9-toolchain-manifest.json` now records this run; the
original bare-metal record remains in that file's git history. Still unexercised: the RHEL
`subscription-manager` and EPEL-on-RHEL branches, and arm64.

### Original reference run (2026-08-15)

Rocky Linux 9.8, 16 cores / 23 GB RAM, `dev` at `c01493d3`, 2026-08-15. The same recipe was also run
end-to-end on `main` at `88f9397d` (the 0.13.0 cut, meson 1.11.1) with the same outcome. Full
provenance — every package version with the repo it came from — was recorded in
`docs/rhel9-toolchain-manifest.json`, which now holds the re-verification (this run's
record lives in that file's git history); everything above `verified_run` in that file is
machine-collected by `--manifest`, and the `verified_run` block is hand-recorded from the session.

| Stage | Result |
|---|---|
| `vcpkg install` (22 ports, **cold**) + `meson setup` | **20.3 min** — grpc 13 min, protobuf 2.8 min, openssl 46 s, abseil 40 s |
| `vcpkg install` (warm) + `meson setup --wipe` | **5 s** |
| `meson compile` (78 targets) | **4.7 min**, 523 warnings, none from vcpkg headers, `werror=false` |
| `meson test` (23 targets) | **10.4 min** — 18 pass, 2 skip, 2 fail (below) |
| libpq linkage (ADR-0008) | no dynamic libpq ✅ |
| Erlang gateway | skipped, rebar3 absent — by design |

The repo's own "~65–70 min cold vcpkg" estimate is calibrated for a smaller machine; 16 cores cut it
to 20 minutes.

> **Timeout headroom:** even when healthy, `server pg unit tests shard B` took **523 s against the
> 600 s meson timeout** of the reference run on this box (700 s on current dev). On a slower machine,
> raise the timeout rather than assuming a
> hang — but check trap 4 first, because a missing `pg_signal_backend` produces a *real* timeout.

### Two remaining failures

**1. `docs — yuzu:ci telemetry selftest`** — the system-SQLite/`RETURNING` limitation described
above. Platform-specific, understood, not fixable from the setup script.

**2. `tests/unit/server/test_mcp_server.cpp:4474`** (dev; `:2270` on main — the case moves between
commits, so match it by name) — *"MCP Agentic demo: classify schema drops phantom mode and never
steers to a write tool (G-S5/G-S6)"*, `CHECK(checked)`. One case out of 500 in shard A; one assertion
out of 9916.

**This is [issue #2610](https://github.com/Tr3kkR/Yuzu/issues/2610), not a RHEL problem** — a known
Linux-only deterministic failure where `classify_operational_question` is missing from `tools/list`
in a readonly session. It was first seen on WSL2/gcc and passes on Windows MSVC at the same commit.

This box supplied the issue's stated first triage step ("run the case on dev HEAD on any Linux box"),
on an independent distro and compiler: it fails on **`dev` @ `c01493d3`** and on **`main` @
`88f9397d`** under Rocky 9.8 / GCC 14.2.1, and reproduces with and without the Postgres test
environment. So it **does** pre-exist on dev, and the platform split is Linux-vs-Windows rather than
anything specific to the RHEL family.

---

## Known limitation: system SQLite is too old for the Python test tooling

RHEL 9 ships **SQLite 3.34.1** (`sqlite-libs-3.34.1`). The `RETURNING` clause landed in **3.35.0**.
The system `python3`'s `sqlite3` module links that system library, so any repo Python tooling that
uses `RETURNING` fails on a stock RHEL 9 box:

```
test_db: SQLite operational error on .../test-runs.db: near "RETURNING": syntax error
```

Concretely this fails the `docs — yuzu:ci telemetry selftest` meson test, and it means
`scripts/test/test_db.py` — the durable test-runs database behind the `/test` skill and the CI
telemetry — cannot record results on this platform.

**Scope: Python only.** The C++ build and test suites are unaffected — they link SQLite **3.52.0**
from vcpkg, not the system library. Nothing about the compiler, the build, or the C++ tests depends
on this.

Installing `python3.11` or `python3.12` from AppStream does **not** fix it — those RPMs link the same
system `sqlite-libs` (their dependency is literally `sqlite-libs >= 3.34.1`). A real fix means a
newer SQLite for Python (source build, or reworking the tooling onto a bundled driver), so on RHEL 9
today this is a documented limitation rather than something the setup script can resolve.

---

## Out of scope

- **The Erlang gateway.** `meson.build` does `find_program('rebar3', required: false)`, so with no
  rebar3 on `PATH` the configure step prints `Erlang gateway: skipped` and the C++ build proceeds
  normally; the `gateway eunit` / `gateway ct` meson tests simply never register. EPEL has Erlang
  26, but CI pins **OTP 28 + rebar3 3.24**, and `scripts/ensure-erlang.sh` only *finds* an existing
  kerl/asdf/brew install — it never downloads one. Adding the gateway means kerl or asdf for OTP 28
  plus a downloaded rebar3 3.24 escript. See `docs/erlang-gateway-build.md`.
- **The UAT rigs.** No container runtime is installed. `podman` + `podman-docker` are available in
  AppStream if you later want `scripts/start-UAT.sh` et al.; `scripts/ci/ensure-postgres.sh` prefers
  a `docker` binary but falls through to the native cluster this recipe provisions.
- **Sanitizer / coverage builds.** `-Db_sanitize=...` works with gcc-toolset-14; the nightly coverage
  job additionally needs `gcovr==8.6`.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `meson.build:1: ERROR: Meson version is 0.63.3 but project requires >=1.3.0` | dnf's meson is on `PATH` ahead of `~/.local/bin`. Source the env file. |
| `PyYAML is required to embed shipped InstructionDefinitions but is not importable from ...` at configure time | `python3` resolved to an interpreter without PyYAML. Check `python3 -c 'import yaml'` with the *same* `python3` meson found. |
| `ERROR: Unknown compiler(s): [['gcc-14']]` | You passed `--native-file meson/native/linux-gcc14.ini`. Use `linux-gcc13.ini`. See trap 2. |
| `collect2: fatal error: cannot find 'ld'` right after `-fuse-ld=mold` | You passed the gcc15 or clang21 native file and mold is not installed. See trap 2. |
| `fatal error: expected: No such file or directory` | gcc-toolset not activated — you are on the system GCC 11. `source /opt/rh/gcc-toolset-14/enable`. |
| `FATAL: Ident authentication failed for user "yuzu"` | `pg_hba.conf` trap 3. |
| `server pg unit tests shard B` TIMEOUT / SIGKILL at its meson timeout | Missing `pg_signal_backend`, trap 4. Check for leaked `yuzu_test_*` databases. |
| `permission denied to terminate process` in test output | Same — trap 4. |
| `near "RETURNING": syntax error` from a Python script | System SQLite is 3.34.1; `RETURNING` needs 3.35+. Known limitation, see above. |
| pip: `Could not find a version that satisfies the requirement meson==1.12.0` (the listed versions stop at 1.11.2) | You asked the 3.9 `python3` for the CI pin. This recipe installs `meson==1.11.2`; the python3.12 route is #3696. |
| `[fail] sudo is required` | Stock container images and minimal installs have no `sudo`. As root: `dnf install -y sudo`. |
| vcpkg `openssl` port fails in `Configure` | Missing perl modules. Install `perl-IPC-Cmd perl-FindBin perl-File-Compare perl-Pod-Html`. |
| vcpkg `libpq` port fails looking for `bison`/`flex` | Those two packages are not installed. |

## Related

- `docs/rhel9-toolchain-manifest.json` — exact provenance of the most recent verified run.
- `docs/windows-build.md`, `docs/darwin-compat.md` — the other two platform runbooks.
- `.github/workflows/ci.yml` — the Ubuntu recipe this one is derived from.
