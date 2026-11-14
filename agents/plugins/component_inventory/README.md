# component_inventory

<!-- BEGIN GENERATED: plugin-doc-gen header -->
<!-- END GENERATED -->

## How it works

`scan` answers one question: which Java archives, and which libraries bundled inside them, sit in the machine-wide application trees of this host. It takes no parameters; the roots come from the OS leg and from nothing a request can supply. The leg reads the mount table once, drops any root that is missing, reached through a link or on a network mount, and walks the rest breadth first without following a link at any path component. Every file ending `.jar`, `.war` or `.ear` is opened once and read in-process: the archive's central directory is parsed, the libraries nested one level deep (`BOOT-INF/lib/`, `WEB-INF/lib/`, `lib/`) are listed from that directory alone, and when the file name carries no version the archive's `pom.properties`, then its `MANIFEST.MF`, supply it. No nested archive is unpacked, no `java` process is started and nothing is written to the host except the plugin's own cost counters. The plugin is not a vulnerability matcher, not a package-manager query and not a view of per-user installs.

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Inventory.Read]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[component_inventory.execute]
  EX --> LIN[Linux leg<br/>link-free walk of the machine roots, archive directory reads]
  EX --> MAC[macOS leg<br/>link-free walk of the machine roots, archive directory reads]
  EX --> WIN[Windows leg<br/>planned: one unsupported status row]
  LIN & MAC & WIN --> ROWS[status row + comp rows + typed result status] --> RS[(ResponseStore)] --> API[REST /api/responses]
```

### What you can decide with it

| Question | Linux | macOS |
|---|---|---|
| Which Java archives are installed under the application trees, at what version? | One row per `.jar`, `.war` or `.ear` under `/opt`, `/usr/share/java`, `/usr/lib/jvm`, `/usr/local/lib`, `/usr/local/share` and `/usr/share/maven` | One row per archive under `/Applications`, `/Library/Java`, `/usr/local` and `/opt/homebrew` |
| Which libraries ride inside an application archive? | One row per nested library, with the path `<archive>!<entry>` and the application folder it belongs to | The same |
| Can this list be trusted as complete? | Yes only when the status is `supported`; `constrained` names the cause | The same |

What a result proves. `supported` means the scan finished with nothing hidden: no bound was reached and every directory and archive was read in full. It does not mean nothing is installed outside the roots above, or in a per-user location. `constrained` means a bound was reached or something could not be read in full, so the list may be incomplete; the rows that were reachable are still returned. A row whose version no source gives is listed with `version_source` `unreadable`; that is a gap in one row and does not make the scan constrained.

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | n/a: the leg is planned and reads nothing | None | n/a | `status\|scan\|unsupported\|windows:planned`, result `UNAVAILABLE` |
| macOS | agent daemon (root under the shipped LaunchDaemon today, `docs/agent-privilege-model.md`) | None expected: application trees under `/Applications`, `/Library/Java`, `/usr/local` and `/opt/homebrew` are normally world-readable (inferred, not measured as the agent account); the mount table read (`getmntinfo_r_np`) needs no grant | See the sample below if one is present for this leg; otherwise not measured | A directory that cannot be listed records `macos:component_inventory:dir_unreadable` and the answer is `constrained`; an archive that cannot be read in full records `macos:component_inventory:archive_unenumerated` |
| Linux | agent daemon, dedicated unprivileged account (`yuzu-agent` on the packaged unit), never root by design (`docs/agent-privilege-model.md`) | None expected: the roots under `/opt` and `/usr` are normally world-readable (inferred, not measured as the packaged account); `/proc/self/mountinfo` is world-readable | See the sample below if one is present for this leg; otherwise not measured | A directory that cannot be listed records `linux:component_inventory:dir_unreadable` and the answer is `constrained`; an unreadable mount table walks nothing and records `linux:component_inventory:mount_table_unreadable` |

No external binaries, no subprocesses, no network use: the plugin lists directories and reads file bytes only. Every directory and file is reached one path component at a time with no link followed. One scan is bounded to 400,000 directory entries, 45 seconds (checked between directories and between archives; a single blocked read is not interrupted), 32 directory levels, 50,000 entries per directory listing, 3,000 rows per application folder and 20,000 rows in all. Per archive, the central directory is read up to 16 MiB, each entry name up to 1,024 bytes, and the `pom.properties` and `MANIFEST.MF` entries up to 64 KiB compressed and 64 KiB inflated.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
<!-- END GENERATED -->

### Outputs

Every row is pipe-delimited. The first row is always `status|scan|<level>|<tokens>` (`level` is `supported`, `constrained` or `unsupported`; `tokens` is comma-joined cause tokens, or `-`). Component rows follow as `comp|java|<name>|<version>|<version_source>|<path>|<size>|<mtime>|<anchor_app>`, one per archive and one per nested library; the first field is `row_kind` (`status` or `comp`) and is the first column below, and on a status row the next columns carry the action name, the level and the tokens. `version` is empty when `version_source` is `unreadable`. `supported` with zero component rows means none was found at the roots; `constrained` means the list may be incomplete. Rows are written at both levels.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
<!-- END GENERATED -->

### Result status

Every read sets a typed result status; a degraded read is `CONSTRAINED`, never an empty `OK`.

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `OK` | full | (empty) | The scan finished with nothing hidden, populated or empty. Informational tokens may still ride the status row without changing the level: `<os>:component_inventory:root_link_skipped` (a root was dropped for a link), `<os>:component_inventory:network_fs_skipped` (a root or a directory inside the tree sat on a network mount and was passed over) and `<os>:component_inventory:version_unreadable` (at least one row has no version) |
| `CONSTRAINED` | partial | `<os>:component_inventory:mount_table_unreadable` / `<os>:component_inventory:budget_entries` / `<os>:component_inventory:budget_time` / `<os>:component_inventory:section_rows` / `<os>:component_inventory:anchor_rows` / `<os>:component_inventory:depth` / `<os>:component_inventory:dir_unreadable` / `<os>:component_inventory:dir_truncated` / `<os>:component_inventory:archive_unenumerated` / `<os>:component_inventory:archive_changed` / `<os>:component_inventory:internal_error` | A bound was reached (`budget_entries`, `budget_time`, `section_rows`, `anchor_rows`, `depth`), a directory could not be listed (`dir_unreadable`) or was cut at its entry cap (`dir_truncated`), an archive could not be enumerated (`archive_unenumerated`: it could not be opened or read, uses ZIP64, has a directory over 16 MiB or a corrupt record) or changed while it was read (`archive_changed`), or the mount table could not be read so nothing was walked (`mount_table_unreadable`). `os` is `linux` or `macos`. The first cause recorded is the one reported. `internal_error` (`linux:component_inventory:internal_error`, `macos:component_inventory:internal_error`, `windows:component_inventory:internal_error`) is the catch-all for an unexpected failure and the command fails |
| `UNAVAILABLE` | unknown | `windows:planned` / `macos:planned` / `linux:planned` | Only the Windows leg is declared planned today (the other two tokens are the shared reporter's and are not emitted by a shipped leg):  the action answers `status\|scan\|unsupported\|windows:planned` and nothing else |

### Where the data goes

- **Instruction result.** Every row is server instruction-result data, with the standard retention policy, served over REST `/api/responses`. Nothing here is a durable server-side table of its own.
- **Not consumed by** the daily sync, Echo, DEX or metrics: the action runs on demand only. The plugin publishes the cost of its last scan as the agent's `yuzu.plugin.component_inventory.*` heartbeat tags (entries walked, rows, milliseconds, roots skipped, links skipped, mounts skipped).
- **Sensitivity.** Rows name the archives and libraries installed on the device, with their versions, paths and application folder names, which is a detailed software inventory for that device. Only machine-wide locations are read; per-user locations are never walked.
- **Siblings:** `crossplatform.software.inventory` (packaged applications) and `crossplatform.runtimes.jvm` (installed Java runtimes).

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
<!-- END GENERATED -->

## Caveats and known gaps

1. **Java archives only, machine roots only.** Python and Node components are not read, and the six roots on Linux and four on macOS are fixed: an archive in a per-user location, a home directory or a custom prefix is not looked for.
2. **No Windows leg yet.** Windows answers one `unsupported` status row (`windows:planned`); a Program Files walk with the same archive reads follows as a later change.
3. **Completeness is bounded, not guaranteed.** A scan that reaches a bound answers `constrained` and returns what it reached; one blocked read inside a directory listing or file read is not interrupted by the 45 second budget. The network-mount guard is a snapshot of a deny-list: a mount that appears after the table was read, a stacked filesystem over a dead mount or a network filesystem type not on the list is not seen.
4. **Nested libraries are one level deep and listed, not read.** Only `BOOT-INF/lib/`, `WEB-INF/lib/` and `lib/` entries ending `.jar` are listed, from the central directory; their version comes from the entry name alone, so a nested library with an unversioned name reads `unreadable`.
5. **Not collected yet.** The daily report does not carry these rows, and there is no customer switch to turn the scan off; both are open items in ADR-0028.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
<!-- END GENERATED -->
