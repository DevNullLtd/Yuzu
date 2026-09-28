# pkg_inventory

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Machine-scope package-manager inventory (managers and packages); per-user package stores are out of scope, deferred to the user-session helper |
| **Version** | 1.0.0 |
| **Kind** | Collector · read-only · gathered (crossplatform.software.package_managers, crossplatform.software.package_manager_packages) |
| **Platforms** | Windows 🟡 planned · macOS ✅ · Linux 🟡 planned |
| **Actions** | `managers` (definition `crossplatform.software.package_managers`) · `packages` (definition `crossplatform.software.package_manager_packages`) |
| **Security** | securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate None |
| **Roles** | execute: endpoint-admin, endpoint-operator · author: content-author |
<!-- END GENERATED -->

## How it works

`managers` reports which package managers are present on the host and their manager-level configuration facts; `packages` lists the macOS Homebrew formulae and casks. Both are pure filesystem reads (`open`/`openat`/`readdir`, no-follow on the prefix directory and on every component below it, so a symlinked prefix or marker is refused, never followed; the OS-owned parents `/opt` and `/usr` are not checked): no `brew`, `dpkg`, `rpm`, `pacman`, `apk` or `winget` is ever spawned. Every action writes a `status` row first, then data rows. On macOS, both actions probe both Homebrew prefixes (`/opt/homebrew` on Apple silicon, `/usr/local` on Intel): `managers` reads directory names under `Library/Taps` (at `<prefix>/Homebrew/Library/Taps` on current Intel installs, where Homebrew keeps its repository, otherwise `<prefix>/Library/Taps`), `Cellar` and `Caskroom`, and `packages` reads `Cellar` and `Caskroom`. Machine scope only: per-user package stores are out of scope, deferred to the user-session helper (ADR-3003). On Linux, `managers` reads nothing and reports `status|managers|unsupported|linux:planned` (caveat 3), and `packages` is unsupported by design (`installed_apps` owns the Linux package roster). On Windows both actions read nothing and report `status|<action>|unsupported|windows:planned` (caveat 5). Every walk takes an injected root (production passes `/`) so the unit suite drives it over a committed fixture tree and through the real emission seam.

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Inventory.Read]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[pkg_inventory.execute]
  EX --> WIN[Windows leg<br/>status row only: windows:planned]
  EX --> MAC[macOS leg<br/>Homebrew Taps / Cellar / Caskroom directory names]
  EX --> LIN[Linux leg<br/>status row only: linux:planned / linux:owned_by_installed_apps]
  WIN & MAC & LIN --> ROWS[status row then data rows + typed result status] --> RS[(ResponseStore)] --> API[REST /api/responses]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `managers` | 🟡 planned · rung 1 · ProgramData\\chocolatey lib/ walk + Program Files\\WindowsApps DesktopAppInstaller folder presence for winget; follows as its own PR | ✅ supported · rung 1 · Homebrew prefix layout: Library/Taps, Cellar, Caskroom | 🟡 planned · rung 1 · tool presence + /var/lib/dpkg/arch, /etc/apt/sources.list.d count, /etc/yum.repos.d count, /etc/dnf/dnf.conf, /etc/pacman.conf + pacman.d/mirrorlist, /etc/apk/repositories + /etc/apk/arch |
| `packages` | 🟡 planned · rung 1 · chocolatey lib/<id>/<id>.nuspec via libxml2; follows as its own PR | ✅ supported · rung 1 · Cellar/<formula>/<version>, Caskroom/<cask>/<version> directory names | ⛔ unsupported · rung 1 · none by design |

**Declared limits per leg** (descriptor fallback text, verbatim):

- **`managers` / Linux** — follows as its own PR
- **`packages` / Linux** — installed_apps.get_inventory_linux owns the Linux package roster
<!-- END GENERATED -->

The capability-matrix rows for this plugin in `docs/os-capability-matrix.md` are rendered from the plugin's own `kActionDescriptors` (`pkg_inventory_plugin.cpp`); the Windows legs and the Linux `managers` leg are declared `planned`, not `supported`.

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, #1442) | None — the leg reads nothing | Not measured — the leg emits only a status row (caveat 5) | n/a — no read is attempted; every action reports `status\|<action>\|unsupported\|windows:planned` |
| macOS | agent daemon, root today (LaunchDaemon carries no `UserName` key — `docs/agent-privilege-model.md` TL;DR); this plugin's own reads need no elevation beyond that default | None documented — Homebrew's `Cellar`, `Caskroom` and `Library/Taps` are ordinary directories | Measured unprivileged (euid 501) on this Mac, 2026-09-22 (`docs/samples/macos.txt`; the walk tests use a real formulae-only capture, `tests/unit/fixtures/wave10/pkg_inventory/macos/provenance.txt`); not yet measured under the root LaunchDaemon identity | A location that exists but cannot be opened or listed makes the status row `constrained` with `macos:<source>:permission_denied` (or another detail token); a missing prefix is zero rows and `supported`, never a failure |
| Linux | agent daemon, default | None — the leg reads nothing | Not measured — the leg emits only a status row for either action (caveat 3) | n/a — no read is attempted; `managers` reports `status\|managers\|unsupported\|linux:planned` and `packages` reports `status\|packages\|unsupported\|linux:owned_by_installed_apps` |

Binaries/subprocesses: none — every read is an in-process filesystem read. Network: none.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
Neither action takes parameters.
<!-- END GENERATED -->

### Outputs

Pipe-delimited rows written via `write_output()`, two shapes per stream discriminated by field 0: exactly one `status|<action>|<supported\|constrained\|unsupported>|<failure tokens or ->` row first, then zero or more data rows — `manager|<name>|<present\|unavailable>|<version or ->|<root_path or ->|<facts k=v;... or ->|<reason or ->` for `managers`, `package|homebrew|<id>|<version>|<formula\|cask>` for `packages`. A genuinely absent manager or prefix is `supported` with zero data rows; an unreadable location is `constrained` with a token, never an empty success. `root_path` is the logical path (`/opt/homebrew`, `/usr/local`), never an injected test root; a manager row's `version` is always `-` in this release (no `brew --version` is run), while a package row's `version` is the real version directory name. A formula or cask present under both prefixes yields one `package|` row per prefix; the package row carries no prefix column — the manager rows say which prefixes exist. Every OS-supplied field goes through the shared escaper `yuzu::util::safe_output_field`; directory names that are dot-prefixed, over 255 bytes, or contain a pipe, backslash, control or non-ASCII character are skipped without a token (Homebrew never creates them), so they never reach a row. This plugin is not in the server's `kKeyValuePlugins` set, so the server does not decode its rows as two-cell `key|rest`; the columns below are the definition's own.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`crossplatform.software.package_manager_packages` — `row_kind|manager|id|version|kind`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `row_kind` | string | `status` `package` | Windows, Linux, macOS | `package` | Row shape discriminator. Values: status (exactly one per result, always first), package (one per installed formula or cask version directory). |
| `manager` | string | - | Windows, Linux, macOS | `homebrew` | Package rows: the owning package manager, always homebrew in this release. Status rows: the action name, always packages. |
| `id` | string | - | Windows, Linux, macOS | `openssl@3` | Package rows: the formula or cask directory name (e.g. openssl@3). Status rows: the completeness level. Values: supported, constrained (at least one read failed or the row cap or walk budget was hit), unsupported (Linux by design, Windows planned). |
| `version` | string | - | Windows, Linux, macOS | `3.4.1` | Package rows: the version directory name under the formula or cask (cask versions may carry commas or colons). Status rows: the comma-joined failure tokens, or "-" when none. Tokens read <os>:<source>:<detail> (e.g. macos:homebrew_cellar:row_cap, macos:homebrew_cellar:byte_cap, macos:homebrew_caskroom:walk_budget or macos:packages:busy), linux:owned_by_installed_apps, windows:planned or pkg_inventory:exception (a leg threw). |
| `kind` | string | `formula` `cask` | macOS | `formula` | Package rows only: whether the directory came from the Cellar or the Caskroom. Values: formula, cask. |

**`crossplatform.software.package_managers` — `row_kind|name|state|version|root_path|facts|reason`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `row_kind` | string | `status` `manager` | Windows, Linux, macOS | `manager` | Row shape discriminator. Values: status (exactly one per result, always first), manager (one per package manager detected). |
| `name` | string | - | Windows, Linux, macOS | `homebrew` | Manager rows: the package manager. Values: dpkg, apt, rpm, dnf, pacman, apk, homebrew. Only homebrew is emitted in this release: Linux managers leg planned; on Linux the status row reports unsupported\|linux:planned and there are no manager rows. Status rows: the action name, always managers. |
| `state` | string | `present` `unavailable` `supported` `constrained` `unsupported` | Windows, Linux, macOS | `present` | Manager rows: present means at least one Homebrew marker directory (Library/Taps, Cellar, Caskroom) under the prefix was readable; unavailable means a marker exists but none could be read (see reason); a prefix root that cannot be opened counts as Homebrew only for /opt/homebrew, since /usr/local exists on every Mac and there the status tokens appear with no manager row. Status rows: the completeness level. Values: supported, constrained (at least one read failed), unsupported (Windows and Linux planned legs). |
| `version` | string | - | Windows, Linux, macOS | `-` | Manager rows: the manager version, or "-" (versions are not read in this release, so always "-"). Status rows: the comma-joined failure tokens, or "-" when none. Tokens read <os>:<source>:<detail> (e.g. macos:homebrew_cellar:permission_denied, macos:homebrew_taps:walk_budget or macos:managers:busy), linux:planned, windows:planned or pkg_inventory:exception (a leg threw). |
| `root_path` | string | - | macOS | `/opt/homebrew` | Manager rows only: the logical root the facts were read from (e.g. /opt/homebrew, /usr/local; /etc/apt once the Linux managers leg lands), never an injected test root; "-" when the manager has no single root (Linux rpm). |
| `facts` | string | - | macOS | `taps=0;formulae=66;casks=0` | Manager rows only: semicolon-separated key=value manager-level facts, or "-". Keys by manager: dpkg architectures=<a,b>; apt sources_list_lines, sources_d_files; dnf repo_files, dnf_conf_lines; pacman pacman_conf_lines, mirrors; apk repositories, tagged, arch; homebrew taps, formulae, casks. A key is omitted when its source could not be read completely (unreadable, truncated at the entry cap, or out of walk budget). Only the homebrew keys are emitted in this release (Linux managers leg planned). |
| `reason` | string | - | macOS | `-` | Manager rows only: failure tokens for an unavailable manager, or "-". |
<!-- END GENERATED -->

### Result status

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `OK` | `FULL` | — | The read completed: managers or packages were found, or none were (an absent manager or prefix is a complete answer, not a degradation). |
| `CONSTRAINED` | `PARTIAL` | `<os>:<source>:<detail>` | At least one location could not be read completely. `<os>` is `macos`; `<source>` names the location (`homebrew_taps`, `homebrew_cellar`, `homebrew_caskroom`); `<detail>` is `permission_denied`, `not_a_directory` (also what a symlink reads as: the kernel answers ENOTDIR to a no-follow directory open of a link), `symlink_refused` (a symlink loop in the path), `io_error`, `entry_cap` (4,096 names per directory) or `enumeration_error` (directory listing truncated or errored: its count fact is omitted, never reported as a lower bound), `row_cap` (20,000 package rows), `byte_cap` (1 MiB of package rows) or `walk_budget` (200,000 entries or 10 s per action; the locations not yet read are skipped and the rows already found are kept). The wall clock is cooperative: it is checked per directory and per listed entry and cannot interrupt a filesystem call that blocks on a stalled mount inside the tree (a very large listing of non-directory entries can overshoot it by the cost of its stat calls), so `<os>:<source>:busy` (source is the action name) means another dispatch of this action is still walking: nothing was read, there are no rows, retry later (at most one walk per action runs at a time). A symlinked Homebrew prefix or marker directory is refused, never followed. Several tokens are comma-joined. |
| `UNAVAILABLE` | `PARTIAL` | `linux:owned_by_installed_apps` | Linux `packages`: unsupported by design; `installed_apps` owns the Linux package roster. |
| `UNAVAILABLE` | `PARTIAL` | `linux:planned` | Linux `managers`: the leg reads nothing and emits only `status\|managers\|unsupported\|linux:planned` (caveat 3). |
| `UNAVAILABLE` | `PARTIAL` | `windows:planned` | Windows, either action: the leg reads nothing and emits only `status\|<action>\|unsupported\|windows:planned` (caveat 5). |
| `UNAVAILABLE` | `PARTIAL` | `pkg_inventory:exception` | Any action, any OS: a leg threw during a read. `execute()` catches it, writes `status\|<action>\|constrained\|pkg_inventory:exception` (the one row whose level is `constrained` while the typed status is UNAVAILABLE: the command failed, rc 1) with this fixed token, never the exception's own text, and never lets the exception cross the plugin ABI. |

### Where the data goes

- **Instruction result.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore, queryable at `/api/responses/{id}`. Both actions are gathered definitions (`crossplatform.software.package_managers` and `crossplatform.software.package_manager_packages`, 300s TTL).
- **Not consumed by** daily-sync, TAR, DEX, or metrics.
- **Sensitivity.** Rows name installed software (Homebrew formula and cask names and versions) and the Homebrew prefixes present on the host with their tap, formula and cask counts — a software inventory by another route. No row carries a username, account name or user-profile path.
- **Siblings:** `installed_apps` (owns the Linux package roster and the macOS application list, and its `list_per_user` also lists Homebrew formulae per user — see caveat 4 for both overlaps) and `software_actions` (installs and removes software; this plugin only reads).

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-22 · euid 501 · leg-hash 57448de65bb7

```
== action=managers
status|managers|supported|-
manager|homebrew|present|-|/opt/homebrew|taps=0;formulae=66;casks=0|-
[result_status] OK / FULL

== action=packages
status|packages|supported|-
package|homebrew|actionlint|1.7.12|formula
package|homebrew|ada-url|4.0.0|formula
package|homebrew|autoconf|2.73|formula
package|homebrew|automake|1.18.1_1|formula
package|homebrew|bash|5.3.15|formula
package|homebrew|blake3|1.8.7|formula
package|homebrew|brotli|1.2.0|formula
package|homebrew|c-ares|1.34.8|formula
package|homebrew|ca-certificates|2026-08-13|formula
package|homebrew|ccache|4.13.6_1|formula
package|homebrew|cmake|4.4.2|formula
… 12 of 67 rows shown
[result_status] OK / FULL
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-22 · euid 0 · leg-hash 57448de65bb7

```
== action=managers
status|managers|unsupported|linux:planned
[result_status] UNAVAILABLE / PARTIAL / linux:planned

== action=packages
status|packages|unsupported|linux:owned_by_installed_apps
[result_status] UNAVAILABLE / PARTIAL / linux:owned_by_installed_apps
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **No documented business driver.** The roadmap verification of 2026-09-19 found zero documented business driver anywhere in the four planning docs for this plugin; it ships as a read-only inventory fact source, not a response to a stated customer requirement.
2. **Machine scope, default prefixes, point in time.** Per-user package stores are out of scope, deferred to the user-session helper (ADR-3003): per-user Homebrew, npm global-versus-user, pip user installs and cargo are not read. Only the two default Homebrew prefixes are probed: a Homebrew relocated to a custom or symlinked prefix reads as absent (zero rows) or refused (`constrained`), not as installed. Names are read from a live tree, so an entry removed between the listing and its classification is skipped as absent, not reported. A stalled mount inside the tree can pin one agent worker per action until it answers (later dispatches report `busy`), because the walk's deadline is cooperative; recover with a normal agent restart ("Stopping a wedged agent", `docs/user-manual/server-admin.md`).
3. **Linux is identity and config only, and `managers` follows as its own PR.** The Linux leg will report which package managers are present and their configuration facts, never a package roster: installed_apps owns the roster, so Linux `packages` is unsupported by design and never emits a `package|` row. Until the Linux `managers` leg lands it reports `status|managers|unsupported|linux:planned` and no manager rows.
4. **Homebrew rows overlap `installed_apps` on macOS, and cask and tap rows are unexercised against real data.** Homebrew casks install `.app` bundles that `installed_apps`' macOS `list` also reports via `system_profiler`, and `installed_apps`' `list_per_user` already lists Homebrew formulae per user as `user_app|brew|<name>|<version>|-|-` (it runs `brew list --versions`); this plugin is the machine-scope, zero-subprocess view of the same store (manager identity, prefixes, cask versions) and does not claim to be disjoint from either. The real-capture host had a populated `Cellar` only (no `Library/Taps`, empty `Caskroom`, no `/usr/local` Homebrew), so tap and cask counting and the Intel prefix are covered only by synthetic in-code layouts that encode the layout the walk assumes, not by a real capture. The Intel `Library/Taps` location (`<prefix>/Homebrew/Library/Taps`) is taken from Homebrew's own scripts, not from an Intel capture. Gating differs on purpose: `installed_apps.list_per_user` is admin-or-approval because it attributes packages to users, whereas this machine-scope roster is `Inventory:Read` (ungated), like `installed_apps.list`.
5. **Windows and Linux `managers` legs planned — each follows as its own PR.** Both Windows actions report `status|<action>|unsupported|windows:planned` and no data rows, and Linux `managers` reports `status|managers|unsupported|linux:planned` and no data rows. The Chocolatey `lib\` directory walk with `.nuspec` metadata, winget presence and the Linux manager identity and config walk follow as their own PRs; nothing for them is built here.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/pkg_inventory/src/pkg_inventory_legs.hpp` · `agents/plugins/pkg_inventory/src/pkg_inventory_linux.cpp` · `agents/plugins/pkg_inventory/src/pkg_inventory_macos.cpp` · `agents/plugins/pkg_inventory/src/pkg_inventory_macos_parsers.hpp` · `agents/plugins/pkg_inventory/src/pkg_inventory_parsers.hpp` · `agents/plugins/pkg_inventory/src/pkg_inventory_plugin.cpp` · `agents/plugins/pkg_inventory/src/pkg_inventory_win.cpp`
- Definitions: `content/definitions/pkg_inventory.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_pkg_inventory.hpp`
- Tests: `tests/unit/test_pkg_inventory_local_dispatcher.cpp` · `tests/unit/test_pkg_inventory_macos_parsers.cpp` · `tests/unit/test_pkg_inventory_parsers.cpp`
- Privilege row: `docs/agent-privilege-model.md`
<!-- END GENERATED -->
