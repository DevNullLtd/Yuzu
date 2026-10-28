# middleware

<!-- BEGIN GENERATED: plugin-doc-gen header -->
<!-- END GENERATED -->

## How it works

`middleware` answers one question per product: which installations of that product are registered on this host, and at what version. It is table-driven. Each product is one row of a compile-time table (`agents/shared/middleware_products.hpp`) that names, per OS, the file that lists the product's installations and the files whose names carry the version; one generic runner turns a row into data rows, so adding a product adds a table row and one action, not new walking code. Today the table holds IBM MQ (`ibm_mq`). On Linux the runner parses the `Installation:` stanzas of `/etc/opt/mqm/mqinst.ini` (`Name` and `FilePath`, values trimmed because the real file pads `Description` with trailing spaces) and lists the file names in each installation's `<FilePath>/swidtag`. The version is read from a file NAME, never from file content: the product's own `ibm.com_IBM_MQ*-<v>.swidtag`, else exactly `IBM_MQ-<v>.mqtag`; the bundled component tags beside them (GSKit, JRE, Runtime, Messages) never name the product. The plugin never starts `dspmqver`, `dspmqinst` or any other process, opens every directory without following symlinks, and does not open a path on, under or containing a network mount that `/proc/self/mountinfo` listed when the action started. That guard is a snapshot: a network filesystem mounted after it is not seen, and if the table cannot be read in full the walk still runs, guarded only by the mounts that were read, and the answer is `constrained` with `linux:middleware:mountinfo:unreadable`. Each action writes one `status` row first, then zero or more installation rows, so an empty list is never inferred from silence. On Windows and macOS the action answers a single `unsupported` status row. The plugin is read-only, does no vulnerability matching (a row is presence plus the version string the installer recorded) and does not detect copies that were unpacked without being registered.

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Inventory.Read]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[middleware.execute]
  EX --> TBL[Product table<br/>one row per product, one action each]
  TBL --> LIN[Linux leg<br/>mqinst.ini stanzas, swidtag file names]
  EX --> PLN["Windows and macOS legs<br/>status row only: planned"]
  LIN & PLN --> ROWS[status row + installation rows + typed result status] --> RS[(ResponseStore)] --> API[REST /api/responses]
```

### What you can decide with it

| Question | Linux | Windows and macOS |
|---|---|---|
| Which IBM MQ installations are registered on this host, and at what version? (`ibm_mq`) | One row per registered installation with product title, installation name, version and install path | Nothing: one `unsupported` row, result status `UNAVAILABLE` |
| Is an out-of-support MQ version installed on this host? | Yes, by comparing the `version` column against your own support list; the plugin attaches no verdict | Not answerable |

What a result proves. A row proves the installation is registered in `mqinst.ini` under that name and path. When its `version` is not `-`, it also proves a product tag carrying that version was in the installation's `swidtag` directory; a `-` version means the directory was absent or unreadable or held no product tag (caveat 4), and the row then proves the registration only. Neither proves the product is running or intact. `supported` with zero rows means no registered installation was found at the places this plugin reads; it does not mean none is installed (caveat 1). `constrained` means a read failed or was refused, so the rows may be incomplete, and the IBM MQ rows are withheld from the installed-software sync for that cycle (caveat 5); read the reason tokens before trusting a negative. For the packaged-application view use `installed_apps`.

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | n/a (the leg reads nothing, caveat 2) | n/a | n/a | n/a (the placeholder answers `status\|<action>\|unsupported\|windows:planned`, result status `UNAVAILABLE`) |
| macOS | n/a (the leg reads nothing, caveat 2) | n/a | n/a | n/a (the placeholder answers `status\|<action>\|unsupported\|macos:planned`, result status `UNAVAILABLE`) |
| Linux | agent daemon, dedicated unprivileged account (`yuzu-agent` on the packaged unit), never root by design (`docs/agent-privilege-model.md`) | `ibm_mq`: none expected, because `/etc/opt/mqm/mqinst.ini` is world-readable and `/opt/mqm/swidtag` is world-listable and readable | MEASURED on a registered IBM MQ Advanced for Developers 9.4.5.0 install (Ubuntu debs, `ubuntu:24.04` container): `/etc/opt/mqm` is 755 root:root, `mqinst.ini` is 644 root:root, `/opt/mqm/swidtag` is 555 mqm:mqm holding 444 files, and an unprivileged account with no extra groups read the file and listed the directory; the four IBM MQ developer images hold only 444 files in `/opt/mqm/swidtag` (`tests/unit/fixtures/middleware/linux/provenance.txt` and `swidtag.listing`); not measured as `yuzu-agent`, nor on another MQ version or distribution | `status\|ibm_mq\|constrained\|linux:middleware:mqinst_ini:permission_denied`; an unreadable `swidtag` directory only blanks that installation's version (`-`). Either way the installed-software sync withholds the IBM MQ rows for that cycle when the answer is `constrained` |

No external binaries, no subprocesses, no shell-out, no network use: the plugin opens directories and reads files only. The enumerator file read is size-capped, the number of installations and file names read per listing is capped, and one action's whole walk is bounded in rows, row text and directory entries visited (`walk:row_cap`). Every path, fixed or taken from file content, must be absolute and plain (no `.`, `..`, empty component or trailing slash) and is opened `O_NOFOLLOW` hop by hop, so a symlink at any hop is refused, never followed.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
<!-- END GENERATED -->

### Outputs

Every row is pipe-delimited. The first row is always `status|<action>|<level>|<reason>` (`level` is `supported`, `constrained` or `unsupported`; `reason` is comma-joined tokens, or `-`). Installation rows follow as `<action>|<title>|<name>|<version>|<install_path>|<edition>`, one per registered installation; the first field is `row_kind` (`status`, or the action name) and is the first column below, and on a status row the next columns carry the action name, the level and the tokens. `supported` with zero rows means none was found at the places read (caveat 1); `constrained` means a read failed or was skipped and the rows may be incomplete, so failure never reads as absent. A field the host did not supply is `-` (the version of an installation whose swidtag directory names no product tag, caveat 4; the edition of every IBM MQ row, which the installer metadata does not carry). Free-text fields go through the shared escaper, so a value containing a pipe or ending in a backslash cannot shift the field count on the server's escape-aware decoder. `middleware` is not in the server's `kKeyValuePlugins` set (`server/core/src/result_parsing.hpp`), so its rows are not decoded as two-cell key and value rows.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
<!-- END GENERATED -->

### Result status

Every read sets a typed result status; a degraded read is `CONSTRAINED`, never an empty `OK`.

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `OK` | full | (empty) | Linux: the read finished with no failure, populated, or none found at the places read (`status\|<action>\|supported\|-` with zero rows) |
| `CONSTRAINED` | partial | `<os>:middleware:<source>:<cause>` / `internal_error` | Linux: one or more enumeration reads failed, were refused or hit a cap, and the rows returned may be incomplete; the tokens are accumulated and comma-joined in the status row. `<source>` is the table's probe id of the failing read (`mqinst_ini`) or `walk` (the row, row-text or directory-entry budget) or `mountinfo` (the mount table could not be read in full); `<cause>` is one of the closed set `permission_denied`, `unreadable`, `oversized`, `symlink_refused`, `malformed`, `network_fs_skipped`, `row_cap` or `internal_error`. A failure confined to one installation (an unreadable or absent swidtag directory, a refused path, no product tag) is logged and leaves that row's version as `-`; it does not constrain the answer. The bare `internal_error` is a caught exception on any leg: it never crosses the plugin boundary and the command returns 1 (a failed command) |
| `UNAVAILABLE` | partial | `windows:planned` / `macos:planned` | Windows and macOS: the leg is not shipped; the action answers `status\|<action>\|unsupported\|<os>:planned` and nothing else |

### Where the data goes

- **Instruction result.** Every row is server instruction-result data, with the standard retention policy, served over REST `/api/responses`.
- **Installed software.** The action feeds the agent's daily installed-software sync (`middleware.ibm_mq`) as ecosystem `ibm_mq`, kind `app`, carrying name, version and publisher only; the install path and edition are not carried. A `constrained` answer withholds the source's rows for the cycle (caveat 5).
- **Not consumed by** TAR, DEX, or metrics.
- **Sensitivity.** Rows name installed IBM MQ installations with their exact version and install path, which is a patch-level software inventory for the device; `name` and `install_path` echo `mqinst.ini` text as found, so a value planted in that file reaches a row after the UTF-8 and pipe scrub.
- **Siblings:** none yet; each further product adds a table row, an action and a `crossplatform.middleware.<id>` definition.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
<!-- END GENERATED -->

## Caveats and known gaps

1. **Only registered installations are listed.** IBM MQ comes from `mqinst.ini`, so an unpacked copy that was never registered with the operating system is not found, and `supported` with zero rows means none was found there. The directory the stanza points at is only read for its version.
2. **The Windows and macOS legs are planned.** Only the Linux leg ships; on Windows and macOS the action reads nothing and answers `status|ibm_mq|unsupported|<os>:planned`.
3. **The `mqinst.ini` form is confirmed on one version.** IBM documents the file's location and content but states its format is not fixed and reserves `dspmqinst` as the interface, which this plugin never runs. The `Installation:` header and the `Name`, `Description`, `Identifier` and `FilePath` spellings are confirmed on one registered 9.4.5.0 install (Ubuntu debs) only; no `Primary` key is read or required. A version or platform that spells them differently surfaces as `linux:middleware:mqinst_ini:malformed` (content but no `Installation:` line, or a stanza without `Name` or `FilePath`), never as a silent empty inventory.
4. **The version comes from the product tag only.** The name is `ibm.com_IBM_MQ*-<v>.swidtag` (or `ibm.com_IBM_WebSphere_MQ*`), else exactly `IBM_MQ-<v>.mqtag`. Bundled-component tags (GSKit, JRE, Runtime, Messages_*) carry their own versions and never name the product, so a directory holding only component tags yields a row with version `-` and a logged `missing`, not a token.
5. **A constrained answer removes the IBM MQ rows for that cycle.** The installed-software sync drops the source when it answers `constrained`, and because the server replaces the agent's whole inventory each cycle, previously stored IBM MQ rows DISAPPEAR until the source recovers. A constrained cycle is visible as missing rows plus the status token, never as stale rows.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
<!-- END GENERATED -->
