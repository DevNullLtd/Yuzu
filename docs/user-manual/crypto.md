# Crypto — Cryptographic Library Inventory

The `/crypto` dashboard shows which cryptographic libraries are installed across the fleet and at
which versions. It answers questions such as "which devices still carry OpenSSL 1.1?" or "where
is GnuTLS installed?" from data Yuzu already collects: the daily-synced
[installed-software inventory](inventory.md) (ADR-0016). No new agent code runs and nothing new
is collected from endpoints.

Each installed package name is matched against a curated table of library families (OpenSSL,
GnuTLS, NSS, Mbed TLS and others, see [The library table](#the-library-table)). The page reports
two facts per family and nothing more: how many distinct devices carry it, and which versions
and package names were seen.

**What this is not.** It is package-level presence evidence. It does not decide whether a library
or a version is acceptable, and it carries no weak, vulnerable, post-quantum or outdated verdicts.
Interpreting a version is left to the reader (or to an agentic worker reading the same data):
Yuzu deliberately keeps the matching mechanical and deterministic, and leaves judgement out of
the product's core. A family that does not appear is not proof that the library is absent (see
[Coverage and limits](#coverage-and-limits)).

## Access

Crypto is an item in the **Posture** group of the sidebar (**Posture > Crypto**), or go to
`/crypto` directly. Permission required: **`Inventory:Read`**, the same permission that gates
the [`/software` and `/inventory` pages](inventory.md).

- **Management-group confinement applies.** A caller confined to management groups sees only
  the devices in their scope, and every figure on the page (family counts, the devices-reporting
  denominator, version buckets and the device drill) is computed over that scope, not filtered
  afterwards. Two operators can legitimately see different counts.
- **Service-scoped API tokens are confined** to the devices their service tag selects, by the
  same mechanism.
- A caller with no `Inventory:Read` grant gets a 403 on the REST routes, and the page shows a
  notice instead of data. The refusal is audited by the access gate (see [Audit](#audit)).

## The page

### KPI strip

Three tiles across the top:

| Tile | Meaning |
|---|---|
| Devices reporting inventory | Devices in your visible scope that have an installed-software report. This is the denominator: a device that has never reported cannot be shown to carry or not carry a library. |
| Devices with a crypto library | Distinct devices in scope with at least one package matching any family. A device carrying `libssl3` and `libgnutls30` counts once here. |
| Families found | Number of curated families with at least one matching device. |

### Families table

One row per family found, ordered by device count (highest first), then family id. Families with
no matching device are omitted.

| Column | Meaning |
|---|---|
| Family | The library family (for example OpenSSL). |
| Devices | Distinct devices carrying any package of the family. A device with both `libssl3` and `openssl` counts once. |
| Versions | Number of distinct (version, ecosystem) buckets. |
| Top versions | The four most-installed version buckets as chips; `+more` when there are others. |

The version list is capped at 50 buckets per family; when it is, the family is flagged
`versions_truncated` in the API. The device count is unaffected by that cap.

If the store's row ceiling (2,000 version rows per read) is reached, the page says so and the
API sets `result_truncated`. Family device counts and the coverage figures are still complete;
only some version rows are missing.

### Devices drill

Click a family row to load the devices carrying it, or click a version chip to narrow to that
exact (version, ecosystem) bucket. Each row is one matching package on one device:

| Column | Meaning |
|---|---|
| Device | Hostname (an em dash when the registry does not know the device) and the agent id. |
| Package | The package name as reported, for example `libssl3`. |
| Version, Release | As reported by the package manager; an em dash when the ecosystem does not store the field. |
| Ecosystem | `deb`, `rpm`, `apk`, `pacman`, `brew`, `windows` and so on. |
| Kind | The inventory row kind (for example `package`). |

A device with several matching packages appears once per package. Rows are ordered by agent id,
then package name, and loaded 100 at a time with a **Load more devices** button.

### The evidence caveat

Every state of the page, including the empty and the error states, carries this notice:

> Package-level evidence only. Statically linked, vendored and OS-bundled copies (for example
> LibreSSL on macOS, or DLLs shipped inside Windows applications) are not visible here.
> Certificates, SSH host keys and protocol settings will arrive in later releases.

## The library table

The mapping from package name to family is a single table in the server
(`server/core/src/crypto_library_model.cpp`). It is the only copy: the database query patterns
are generated from it, and the per-row results are re-checked against it. The current revision is
**`table_version` 1**, returned in every summary response. A client that stores results can use
it to tell which mapping produced them; the number is bumped on any edit to the table.

**How a name is matched.** The package name is lowercased (ASCII) and compared with each rule
of the table. A rule is either *exact* (the whole name must equal the value) or *prefix* (the
name must start with the value). The first matching rule wins, and the table is built so that no
package name matches two families. Matching is on the package name only, never on the version,
publisher or file contents. A prefix rule also matches the related packages that share the
prefix (for example `libssl-dev` matches the `libssl` rule), because the inventory records
package presence, not what is loaded in memory.

| Family id | Display name | Exact names | Prefixes |
|---|---|---|---|
| `openssl` | OpenSSL | `openssl`, `openssl-libs`, `openssl1.1`, `openssl3`, `openssl3-libs`, `libopenssl3` | `libssl`, `libcrypto`, `openssl@` (Homebrew), `win32 openssl`, `win64 openssl` (Windows installers) |
| `libressl` | LibreSSL | | `libressl` |
| `boringssl` | BoringSSL | | `boringssl` |
| `gnutls` | GnuTLS | `gnutls` | `libgnutls`, `gnutls-` |
| `nss` | NSS | `nss`, `nss-softokn`, `nss-softokn-freebl`, `nss-util`, `nss-sysinit`, `libnss3`, `libnss3-tools` | |
| `mbedtls` | Mbed TLS | `mbedtls` | `libmbedtls`, `libmbedcrypto`, `libmbedx509` |
| `wolfssl` | wolfSSL | `wolfssl` | `libwolfssl` |
| `libgcrypt` | Libgcrypt | | `libgcrypt` |
| `libsodium` | libsodium | | `libsodium` |
| `nettle` | Nettle | `nettle` | `libnettle` |
| `botan` | Botan | | `botan`, `libbotan` |
| `bouncycastle` | Bouncy Castle | | `bouncycastle`, `libbcprov`, `bcprov` |

**Deliberate exclusions.** The `nss` family is exact-names only. A `nss` prefix rule would also
match `nss-mdns` and `nss-pam-ldapd`, which are name-service switch plugins and not
cryptography, so they do not appear. The same care is taken everywhere else: a rule is added only
where the package name reliably denotes the library. A cryptographic library that is not in the
table (for example one bundled under a different name) is not reported.

On Windows, installers from the Shining Light OpenSSL distribution register display names such as
`Win64 OpenSSL v3.x`, which the `win64 openssl` and `win32 openssl` prefixes match. The prefix
`openssl ` alone is not used for Windows.

## Coverage and limits

The data comes from the installed-software daily sync, so what appears depends on what each
operating system's package source records:

| OS | What appears |
|---|---|
| Linux | Packages from `dpkg` (`deb`), `rpm`, `apk` and `pacman`; snaps and flatpaks (the table rarely matches these). |
| macOS | Homebrew formulae (`brew`, for example `openssl@3`) and applications and packages from `system_profiler`. |
| Windows | Applications registered in the `HKLM` and agent-account `HKCU` uninstall keys. |

What never appears:

- **Statically linked libraries.** A binary that embeds its own copy of a library has no package
  record for it.
- **Vendored or bundled copies**, including DLLs shipped inside Windows applications and
  libraries bundled with an application on any OS.
- **OS-shipped libraries that are not packages.** macOS ships LibreSSL and BoringSSL as part of
  the operating system; neither is a package, so neither is listed.
- Anything on a device that has not completed an inventory sync. Compare "Devices reporting
  inventory" with the size of your fleet before reading a count.

A "supported" inventory source that returns zero matching rows means "no matching package rows in
your visible inventory", not "the library is absent". The page, the API and the MCP tools all say
it that way. The inventory sync also keeps its last good state when a collection cycle fails, so
a figure can be up to one daily sync old.

## Agentic access

Both views are available to agentic workers with the same data and the same permission.

### REST

| Route | Purpose |
|---|---|
| `GET /api/v1/crypto/libraries` | Family summary: devices per family, version buckets, coverage. Optional `family`, `ecosystem`. |
| `GET /api/v1/crypto/libraries/devices` | One family's devices, paged. Required `family`; optional `version`, `ecosystem`, `cursor`, `limit` (1 to 1000, default 100). |

Full parameters, response shapes and error tables are in [rest-api.md](rest-api.md#crypto).

### MCP

| Tool | Mirrors | Notes |
|---|---|---|
| `get_crypto_libraries` | `GET /api/v1/crypto/libraries` | Args `family` (one of the twelve family ids) and `ecosystem` (at most 32 characters), both optional. |
| `list_crypto_library_devices` | `GET /api/v1/crypto/libraries/devices` | Args `family` (required), `version` (at most 128 characters), `ecosystem`, `cursor` (at most 2048 characters), `limit` (1 to 1000). |

Both tools are read-only. The intended chain is `get_crypto_libraries`, then
`list_crypto_library_devices` for the family or version bucket of interest. They take **strict
input**: an unknown family, a wrong JSON type, an over-long string or a `limit` outside 1 to 1000
is refused with an invalid-params error, where the REST routes clamp `limit` instead. Both return
the same JSON as the REST `data` object, so a result can be compared across surfaces. See
[mcp.md](mcp.md) for the tool table.

## Audit

Every read that serves data is written to the audit log (see [audit-log.md](audit-log.md)):

| Verb | Written when |
|---|---|
| `crypto.libraries.view` | The family summary is served (REST route and `/crypto` page). The MCP tool writes `mcp.get_crypto_libraries`. |
| `crypto.libraries.devices` | A page of one family's devices is served (REST route and the drill). The MCP tool writes `mcp.list_crypto_library_devices`. |

The row carries the correlation id, the family, the row count and the filters; a continuation page
(one reached with a cursor) is tagged `page=continuation`, so a cursor walk cannot go unrecorded.
A store failure writes a `failure` row.

Auditing is **set-and-proceed**: if the audit row cannot be written, the data is still served,
and the response says so. On REST the body carries `"audit_persisted": false` and the response has
the header `Sec-Audit-Failed: true`; the MCP tools set `audit_persisted: false` in their result.
A refusal at the access gate (no `Inventory:Read` grant, authorization store unavailable) is
written by the gate itself as `auth.fleet_read_required` and is not duplicated here.

## Failure behavior

Reads are authoritative. When the inventory store cannot be read, the answer is an error and never
an empty list, because an empty list would read as "no library installed".

- **REST:** `503` with the A4 error envelope and `retry_after_ms: 5000`. Bad parameters (an
  unknown family, a repeated parameter, a non-integer `limit`, a cursor issued for a different
  filter, over-long or non-UTF-8 values) are `400`.
- **MCP:** a retryable internal error carrying the store-fault retry hint; bad arguments are
  invalid-params.
- **Dashboard fragments** always answer HTTP 200 so the page can show the problem in place: a
  "unavailable" banner with a **Retry** button for a store failure, and a plain notice box for
  a refused permission or a bad parameter.

## Roadmap

The following are planned and not yet available. No dates are committed.

- A fleet certificate inventory with full X.509 fields (the endpoint `certificates` plugin
  already lists system store certificates per device; a fleet-wide view is planned).
- SSH key inventory (host keys and keys at rest) and SSH login evidence.
- Protocol and configuration settings (for example TLS and SSH daemon settings).
- A cryptographic bill of materials (CBOM) export.

These will be shown on this page alongside the library view, under the same permission and
audit model unless stated otherwise at release.

## Related documentation

- [Inventory](inventory.md): the installed-software data this page reads
- [REST API: Crypto](rest-api.md#crypto)
- [MCP tools](mcp.md)
- [Audit log](audit-log.md)
- [Device management](device-management.md)
