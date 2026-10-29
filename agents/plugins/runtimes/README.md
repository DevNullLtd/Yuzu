# runtimes

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Installed .NET and JVM runtime inventory |
| **Version** | 1.0.0 |
| **Kind** | Collector · read-only · gathered (crossplatform.runtimes.dotnet, crossplatform.runtimes.jvm) |
| **Platforms** | Windows 🟡 planned · macOS 🟡 planned · Linux ✅ |
| **Actions** | `dotnet` (definition `crossplatform.runtimes.dotnet`) · `jvm` (definition `crossplatform.runtimes.jvm`) |
| **Security** | securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate None |
| **Roles** | execute: endpoint-admin, endpoint-operator · author: content-author |
<!-- END GENERATED -->

## How it works

`dotnet` and `jvm` each answer one question: which .NET or Java runtimes are installed on this host. On Linux the plugin walks a fixed list of install roots and reads names and small metadata files only; it never starts `java` or `dotnet`. `dotnet` lists the `shared/<framework>/<version>` and `sdk/<version>` directory names under `/usr/share/dotnet`, `/usr/lib/dotnet` and `/usr/lib64/dotnet`. `jvm` reads the `release` file of every home under `/usr/lib/jvm`, `/opt/java`, `/usr/lib64/jvm` and `/var/opt/java`; a home that has a java binary but no `release` file (some distribution OpenJDK 8 packages) is still listed, with version `-` and a `release_missing` constraint. Every directory is opened without following symlinks, and a root on, under or containing a network mount is not opened at all. Each action writes one `status` row first, then zero or more runtime rows, so an empty list is never inferred from silence. On macOS and Windows both actions answer a single `unsupported` status row. The plugin is read-only, does no vulnerability matching (a row is presence and the upstream version string, not an assessment) and does not detect runtimes embedded inside other applications such as Electron or Node bundles. The `vendor` field of `jvm` is the build's self-reported `IMPLEMENTOR` string: an input to a licensing review, not proof of the licence.

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Inventory.Read]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[runtimes.execute]
  EX --> LIN[Linux leg<br/>no-follow directory walks and release file reads]
  EX --> PLN["macOS and Windows legs<br/>status row only: planned"]
  LIN & PLN --> ROWS[status row + runtime rows + typed result status] --> RS[(ResponseStore)] --> API[REST /api/responses]
```

### What you can decide with it

| Question | Linux | macOS and Windows |
|---|---|---|
| Which .NET shared frameworks and SDKs are installed, and at what exact version? (`dotnet`) | One row per framework or SDK version directory under the three roots, including hosts where no package manager owns the install | Nothing: one `unsupported` row, result status `UNAVAILABLE` |
| Which JVMs are installed, JDK or JRE, which version, from which vendor? (`jvm`) | One row per home under the four roots; flavour and vendor come from the `release` file, so Debian and SUSE builds report flavour `unmodelled` | Nothing, as above |
| Is an end-of-life runtime installed on this host? | Yes, by comparing the `version` column against your own support list; the plugin attaches no verdict | Not answerable |

What a result proves. `supported` with zero runtime rows means none was found at the standard roots; it does not mean none is installed (a runtime in `/usr/java`, under a version manager in a home directory or in a custom prefix is not walked). `constrained` means a read failed, was skipped (a network mount) or hit a cap, so the rows may be incomplete; read the reason tokens before trusting a negative. A runtime reachable only through a symlinked alias entry can be missed (caveat 2). For the packaged-application view use `installed_apps`; for a licensing probe use `license_scan`.

### Diagrams

#### One action's walk

```mermaid
flowchart TD
  S[Read mount table once] --> R[Next candidate root]
  R --> N{Root on, under or containing a network mount?}
  N -- yes --> SK[Skip root and record network_fs_skipped]
  N -- no --> O[Open root hop by hop without following links]
  O --> Q{Opened?}
  Q -- absent --> R
  Q -- refused or failed --> F[Record the failure token]
  Q -- opened --> W[List entries and read release files within the caps]
  W --> B{Whole-walk row, byte or visited-entry budget spent?}
  B -- yes --> RC[Stop the walk and record row_cap]
  B -- no --> R
  SK --> R
  F --> R
  R -- no roots left --> D[Write status row then runtime rows]
  RC --> D
```

The mount table is read once per dispatch. A candidate on a network mount is never touched, because an open on a dead hard mount would pin one of the agent's shared command workers. The caps apply across all roots and nesting levels together, so a large tree ends the walk with `row_cap` and a `CONSTRAINED` result rather than a silent truncation. A single directory that exceeds its own entry cap also records `row_cap`, but the walk carries on with the remaining directories.

#### How a JVM home becomes a row

```mermaid
flowchart TD
  H[A directory under a JVM root] --> RF{release file}
  RF -- present and readable --> V{JAVA_VERSION or JAVA_RUNTIME_VERSION present?}
  V -- yes --> ROW[Row with version, flavour and vendor]
  V -- no --> UP[No row, record release_unparsable]
  RF -- unreadable or oversized --> RE[No row, record the read failure]
  RF -- absent --> BJ{bin/java or jre/bin/java is a file or link?}
  BJ -- yes --> RM["Row with version - and flavour unmodelled, record release_missing"]
  BJ -- no --> NH[Not a JVM home, silently ignored]
```

A home with no `release` file is only reported when a java binary proves it is a JVM, and then it carries no version: the plugin does not run `java -version`. Such a host reads `constrained` for as long as the package is installed.

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `dotnet` | 🟡 planned · rung 1 · NDP release-key table + dotnet InstalledVersions + Program Files walk | 🟡 planned · rung 1 · /usr/local/share/dotnet/shared walk | ✅ supported · rung 1 · /usr/share/dotnet, /usr/lib/dotnet, /usr/lib64/dotnet shared/<framework>/<version> and sdk/<version> directory walk; network mounts skipped via /proc/self/mountinfo |
| `jvm` | 🟡 planned · rung 1 · JavaSoft keys + Program Files\\Java walk | 🟡 planned · rung 1 · /Library/Java/JavaVirtualMachines/*/Contents/Info.plist JavaVM dict + Contents/Home/release | ✅ supported · rung 1 · <home>/release file reads under /usr/lib/jvm, /opt/java, /usr/lib64/jvm, /var/opt/java (bin/java probe when a home has no release); network mounts skipped via /proc/self/mountinfo |

**Declared limits per leg** (descriptor fallback text, verbatim):

- **`dotnet` / Windows** — planned; the action answers a single unsupported status row on this OS
- **`dotnet` / macOS** — planned; the action answers a single unsupported status row on this OS
- **`jvm` / Windows** — planned; the action answers a single unsupported status row on this OS
- **`jvm` / macOS** — planned; the action answers a single unsupported status row on this OS
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | n/a (the leg reads nothing, caveat 1) | n/a | n/a | n/a (the placeholder answers `status\|<action>\|unsupported\|windows:planned`, result status `UNAVAILABLE`) |
| macOS | n/a (the leg reads nothing, caveat 1) | n/a | n/a | n/a (the placeholder answers `status\|<action>\|unsupported\|macos:planned`, result status `UNAVAILABLE`) |
| Linux | agent daemon, dedicated unprivileged account (`yuzu-agent` on the packaged unit), never root by design (`docs/agent-privilege-model.md`) | None expected: the stock install trees under `/usr`, `/opt` and `/var/opt/java` are expected to be world-readable (0755 directories, 0644 `release` files; inferred, not measured as `yuzu-agent`) | Walked trees are captured as test fixtures (`tests/unit/fixtures/wave10/runtimes/linux/provenance.txt`); the live sample was taken as `euid 0` in a container, not as `yuzu-agent` | `status\|<action>\|constrained\|linux:runtimes:permission_denied`; rows read before the refusal are still returned, and a later readable root never hides it |

No external binaries, no subprocesses, no shell-out, no network use: the plugin opens directories and reads files only. Every directory is opened `O_NOFOLLOW` hop by hop and listed with a per-directory entry cap of 16,384; a `release` read is bounded to 64 KiB and each recognised value to 256 bytes; one action's whole walk is bounded to 4,096 rows, 1 MiB of row text and 65,536 directory entries visited (`row_cap`). A root on, under or containing a network mount (by filesystem type, from `/proc/self/mountinfo`) is not opened and records `network_fs_skipped`; caveat 5 lists what that guard cannot see.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
Neither action takes parameters.
<!-- END GENERATED -->

### Outputs

Every row is pipe-delimited. The first row is always `status|<action>|<level>|<reason>` (`level` is `supported`, `constrained` or `unsupported`; `reason` is comma-joined tokens, or `-`). Runtime rows follow as `<action>|<flavour>|<version>|<install_path>|<vendor>`, one per runtime found; the first field is `row_kind` (`status`, or the action name) and is the first column below. `supported` with zero runtime rows means none was found at the standard roots (caveat 3 lists what is not walked); `constrained` means a read failed or was skipped and the rows may be incomplete, so failure never reads as absent. A field the host did not supply is `-`, and every flavour mapper has a named `unmodelled` value distinct from no data. Free-text fields (`version`, `install_path`, `vendor`) go through `yuzu::util::safe_output_field`, so a value containing a pipe or ending in a backslash cannot shift the field count on the server's escape-aware decoder. `runtimes` is not in the server's `kKeyValuePlugins` set (`server/core/src/result_parsing.hpp`), so its rows are not decoded as two-cell key and value rows.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`crossplatform.runtimes.dotnet` — `row_kind|flavour|version|install_path|vendor`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `row_kind` | string | `status` `dotnet` | Linux | `dotnet` | Row shape discriminator (the wire row's leading tag). Values: status (exactly one per result, always first), dotnet (one per runtime found). |
| `flavour` | string | `core` `sdk` `unmodelled` | Linux | `core` | Runtime kind. Values: core (a Microsoft.NETCore.App, Microsoft.AspNetCore.App or Microsoft.WindowsDesktop.App shared framework), sdk (an SDK install), unmodelled (any other shared-framework name — reported, never dropped). The three core frameworks all read core at the same version; the install path tells them apart. Status rows: the action name. |
| `version` | string | - | Linux | `8.0.31` | Version taken from the install directory name (e.g. 8.0.31, or a preview build such as 9.0.100-preview.1.24101.2). Status rows: the level (supported, constrained or unsupported). |
| `install_path` | string | - | Linux | `/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.31` | Absolute path of the framework or SDK version directory the version was read from. Status rows: the comma-joined failure tokens, or -. |
| `vendor` | string | - | Linux | `-` | Always "-" for dotnet: the install tree carries no vendor field. |

**`crossplatform.runtimes.jvm` — `row_kind|flavour|version|install_path|vendor`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `row_kind` | string | `status` `jvm` | Linux | `jvm` | Row shape discriminator (the wire row's leading tag). Values: status (exactly one per result, always first), jvm (one per runtime found). |
| `flavour` | string | `jdk` `jre` `unmodelled` | Linux | `jdk` | Image kind from the IMAGE_TYPE key of the release file. Values: jdk, jre, unmodelled (the file does not say — Debian and SUSE OpenJDK release files have no IMAGE_TYPE, and a release-less home has no file at all; never guessed from the path). Status rows: the action name. |
| `version` | string | - | Linux | `17.0.20` | JAVA_VERSION from the release file, falling back to JAVA_RUNTIME_VERSION. A release file with neither key yields no row and a release_unparsable constraint; a home with a java binary but no release file yields - and a release_missing constraint. Status rows: the level (supported, constrained or unsupported). |
| `install_path` | string | - | Linux | `/opt/java/openjdk` | Absolute path of the JVM home directory. Status rows: the comma-joined failure tokens, or -. |
| `vendor` | string | - | Linux | `Eclipse Adoptium` | IMPLEMENTOR from the release file (e.g. Eclipse Adoptium, Debian), self-reported by the build and not verified, or "-" when the key is absent (or the home has no release file). |
<!-- END GENERATED -->

### Result status

Every read sets a typed result status; a degraded read is `CONSTRAINED`, never an empty `OK`.

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `OK` | full | (empty) | Linux: the read finished with no failure, populated, or none found at the standard roots (`status\|<action>\|supported\|-` with zero rows) |
| `CONSTRAINED` | partial | `linux:runtimes:permission_denied` / `linux:runtimes:symlink_refused` / `linux:runtimes:not_a_directory` / `linux:runtimes:open_failed` / `linux:runtimes:stat_failed` / `linux:runtimes:read_failed` / `linux:runtimes:row_cap` / `linux:runtimes:not_regular` / `linux:runtimes:oversized` / `linux:runtimes:field_oversized` / `linux:runtimes:release_unparsable` / `linux:runtimes:release_missing` / `linux:runtimes:network_fs_skipped` / `linux:runtimes:mountinfo_unreadable` / `internal_error` | Linux: one or more reads failed, were refused or skipped (a network mount), or hit a cap, and the rows returned may be incomplete; the tokens of every root are accumulated and comma-joined in the status row. `internal_error` is a caught exception on any leg: it never crosses the plugin boundary and the command returns 1 (a failed command) |
| `UNAVAILABLE` | partial | `macos:planned` / `windows:planned` | macOS and Windows: the leg is not shipped; the action answers `status\|<action>\|unsupported\|<os>:planned` and nothing else |

### Where the data goes

- **Instruction result.** Every row is server instruction-result data — the standard retention policy, served over REST `/api/responses`. Nothing here is a durable server-side table of its own.
- **Not consumed by** daily-sync, TAR, DEX, or metrics — the plugin runs only on an explicit instruction dispatch and there is no agent daily-sync source for runtimes.
- **Sensitivity.** Rows name installed runtimes with their exact version, install path and vendor, which is a patch-level and licensing-relevant software inventory for the device. The Linux leg reads only fixed machine-scope roots (`/usr`, `/opt`, `/var/opt/java`) and the mount table `/proc/self/mountinfo` (used only to decide what to skip, never emitted), so no user-profile root is walked; `install_path` and `vendor` echo directory and file text as found, so a name planted under those roots reaches a row after the UTF-8 and pipe scrub (`yuzu::util::sanitize_utf8` replaces invalid lead and continuation bytes but still passes overlong, surrogate and out-of-range sequences that protobuf rejects: #4864).
- **Siblings:** `crossplatform.runtimes.dotnet`, `crossplatform.runtimes.jvm`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-24 · euid 0 · leg-hash 5cadaa03e74e

```
== action=dotnet
status|dotnet|supported|-
[result_status] OK / FULL

== action=jvm
status|jvm|supported|-
[result_status] OK / FULL
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **macOS and Windows legs are planned.** Only the Linux leg ships; on macOS and Windows both actions read nothing and answer `status|<action>|unsupported|<os>:planned`. .NET Framework (the Windows registry family) is not covered until the Windows leg exists, and the flavour vocabulary above is the Linux subset.
2. **Runtimes reachable only through an alias entry are not listed.** A framework, version or JVM home entry that is itself a symlink (Debian `default-java`, Fedora `java`) is skipped silently because its real directory is a sibling entry. A runtime reachable only through such a link is missed, while a symlink at a candidate root that is not a same-action alias is a `symlink_refused` constraint, not a skip.
3. **Only standard locations are walked.** `dotnet` reads `/usr/share/dotnet`, `/usr/lib/dotnet` and `/usr/lib64/dotnet`; `jvm` reads `/usr/lib/jvm`, `/opt/java`, `/usr/lib64/jvm` and `/var/opt/java`. A runtime installed elsewhere (an Oracle RPM under `/usr/java`, a version manager in a home directory, a custom prefix) is not found by design, since the plugin does not search user profiles, so `supported` with zero rows means none found at these roots.
4. **Some OpenJDK 8 packages ship no `release` file.** Ubuntu 22.04 `openjdk-8-jre-headless`, Rocky 9 `java-1.8.0-openjdk-headless` and Alpine 3.20 `openjdk8-jre-base` were measured to ship none. Such a home is reported with version `-`, flavour `unmodelled` and `release_missing`, so the host reads `constrained` while it is installed; the `install_path` names the major, and reading the real version would need the package manager or `java -version`, which this plugin never uses.
5. **Network mounts are skipped from a dispatch-start snapshot.** A root on, under or containing a mount of a listed network type (`nfs`, `cifs`, `smb3`, `9p`, `virtiofs`, `autofs`, network `fuse.*` and others in `yuzu::shared::is_network_fstype`) is never opened, so a healthy network-mounted JDK is skipped too, and a host whose `/` is a network or virtiofs mount skips every root. The guard cannot see a mount that appears after the snapshot, a stacked filesystem such as an overlay over a dead network mount, an unlisted network type or a hang on a local block device; each can pin one of the agent's shared command workers until the kernel returns, and an unreadable mount table (`mountinfo_unreadable`) leaves the walk guarded only by the mounts read (#4875).

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/runtimes/src/runtimes_legs.hpp` · `agents/plugins/runtimes/src/runtimes_linux.cpp` · `agents/plugins/runtimes/src/runtimes_linux_parsers.hpp` · `agents/plugins/runtimes/src/runtimes_macos.cpp` · `agents/plugins/runtimes/src/runtimes_parsers.hpp` · `agents/plugins/runtimes/src/runtimes_plugin.cpp` · `agents/plugins/runtimes/src/runtimes_win.cpp`
- Definitions: `content/definitions/runtimes.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_runtimes.hpp`
- Tests: `tests/test_runtimes_definition.py` · `tests/unit/test_runtimes_linux_parsers.cpp` · `tests/unit/test_runtimes_local_dispatcher.cpp` · `tests/unit/test_runtimes_parsers.cpp`
- Privilege row: `docs/agent-privilege-model.md`
<!-- END GENERATED -->
